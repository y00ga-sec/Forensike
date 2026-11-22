"""lsass_extract — crash dump → LSASS minidump → pypykatz

Bridge between volatility3 (crash dump parser) and pypykatz
(credential extractor).  This is Forensike's custom "mimilib"
for Linux.

Pipeline:
  1. vol3 opens the crash dump and finds LSASS
  2. vol3 dumps LSASS virtual memory + module list
  3. MinidumpBuilder writes a valid MDMP file from that data
  4. pypykatz parses the minidump → NT hashes + .kirbi tickets

The minidump builder is the key piece — it produces the exact
binary format that pypykatz expects (MDMP header, SystemInfo,
ModuleList, Memory64List streams).
"""

import argparse
import io
import os
import re
import struct
import subprocess
import sys
from pathlib import Path


# ══════════════════════════════════════════════════════════════════════
# Minidump format constants
# ══════════════════════════════════════════════════════════════════════

MDMP_SIGNATURE      = 0x504D444D   # 'MDMP'
MDMP_VERSION        = 0xA793
MDMP_IMPL_VERSION   = 0x0000

# Stream types
STREAM_SYSTEM_INFO   = 7
STREAM_MODULE_LIST   = 4
STREAM_MEMORY64_LIST = 9

# Architectures
ARCH_AMD64 = 9
ARCH_INTEL = 0

# Platform
PLATFORM_WIN32_NT = 2


# ══════════════════════════════════════════════════════════════════════
# Virtual address space built from vol3 memmap output
# ══════════════════════════════════════════════════════════════════════

class VirtualAddressSpace:
    """Map virtual addresses to offsets in the raw memory dump file."""

    def __init__(self, regions, dump_path):
        self.dump_path = Path(dump_path)
        self._map = []          # (vaddr, size, file_offset)
        offset = 0
        for vaddr, size in regions:
            self._map.append((vaddr, size, offset))
            offset += size

    def read(self, vaddr, size):
        """Read *size* bytes starting at virtual address *vaddr*."""
        for region_va, region_sz, file_off in self._map:
            if region_va <= vaddr < region_va + region_sz:
                off_in_region = vaddr - region_va
                available     = region_sz - off_in_region
                read_sz       = min(size, available)
                with open(self.dump_path, "rb") as fh:
                    fh.seek(file_off + off_in_region)
                    return fh.read(read_sz)
        return None

    def read_all_regions(self):
        """Yield (virtual_addr, data_bytes) for every mapped region."""
        with open(self.dump_path, "rb") as fh:
            for vaddr, size, file_off in self._map:
                fh.seek(file_off)
                yield vaddr, fh.read(size)


# ══════════════════════════════════════════════════════════════════════
# PE header helper
# ══════════════════════════════════════════════════════════════════════

def pe_timestamp(addr_space, base_addr):
    """Read a module's PE TimeDateStamp from its in-memory header."""
    dos = addr_space.read(base_addr, 0x40)
    if not dos or len(dos) < 0x40 or dos[:2] != b"MZ":
        return 0
    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    pe = addr_space.read(base_addr + e_lfanew, 24)
    if not pe or len(pe) < 24 or pe[:4] != b"PE\x00\x00":
        return 0
    return struct.unpack_from("<I", pe, 8)[0]


# ══════════════════════════════════════════════════════════════════════
# Minidump builder
# ══════════════════════════════════════════════════════════════════════

class MinidumpBuilder:
    """Create a Windows Minidump (.dmp) file from raw LSASS data.

    Produces the three streams pypykatz needs:
      - SystemInfoStream   (OS version → structure selection)
      - ModuleListStream   (DLL base addresses + timestamps)
      - Memory64ListStream (actual LSASS virtual memory pages)
    """

    def __init__(self):
        self.arch     = ARCH_AMD64
        self.os_major = 10
        self.os_minor = 0
        self.os_build = 19041
        self.n_cpus   = 1
        self.modules  = []     # (name:str, base:int, size:int, timestamp:int)
        self.regions  = []     # (virtual_addr:int, data:bytes)

    def set_sysinfo(self, arch, major, minor, build, n_cpus=1):
        self.arch     = arch
        self.os_major = major
        self.os_minor = minor
        self.os_build = build
        self.n_cpus   = n_cpus

    def add_module(self, name, base, size, timestamp=0):
        self.modules.append((name, base, size, timestamp))

    def add_region(self, virtual_addr, data):
        self.regions.append((virtual_addr, data))

    def write(self, path):
        """Assemble and write the minidump file."""
        buf = io.BytesIO()
        n_streams = 3

        HEADER_SZ = 32
        DIR_SZ    = 12 * n_streams
        buf.seek(HEADER_SZ + DIR_SZ)

        stream_dir = []   # (type, data_size, rva)

        # ---- SystemInfoStream ----
        rva = buf.tell()
        blob = self._pack_sysinfo()
        buf.write(blob)
        stream_dir.append((STREAM_SYSTEM_INFO, len(blob), rva))

        # ---- Module name strings (MINIDUMP_STRING) ----
        name_rvas = []
        for name, _, _, _ in self.modules:
            name_rvas.append(buf.tell())
            encoded = name.encode("utf-16-le")
            buf.write(struct.pack("<I", len(encoded)))
            buf.write(encoded)
            buf.write(b"\x00\x00")

        # ---- ModuleListStream ----
        rva = buf.tell()
        blob = self._pack_modules(name_rvas)
        buf.write(blob)
        stream_dir.append((STREAM_MODULE_LIST, len(blob), rva))

        # ---- Memory64ListStream ----
        rva = buf.tell()
        n_rgn = len(self.regions)
        desc_sz    = 16 * n_rgn
        stream_sz  = 8 + 8 + desc_sz
        base_rva   = rva + stream_sz

        buf.write(struct.pack("<Q", n_rgn))
        buf.write(struct.pack("<Q", base_rva))
        for vaddr, data in self.regions:
            buf.write(struct.pack("<QQ", vaddr, len(data)))
        stream_dir.append((STREAM_MEMORY64_LIST, stream_sz, rva))

        # ---- Memory page data (contiguous) ----
        for _, data in self.regions:
            buf.write(data)

        # ---- Write header + directory at the top ----
        buf.seek(0)
        buf.write(struct.pack("<I",  MDMP_SIGNATURE))
        buf.write(struct.pack("<HH", MDMP_VERSION, MDMP_IMPL_VERSION))
        buf.write(struct.pack("<I",  n_streams))
        buf.write(struct.pack("<I",  HEADER_SZ))
        buf.write(struct.pack("<I",  0))                 # CheckSum
        buf.write(struct.pack("<I",  0))                 # TimeDateStamp
        buf.write(struct.pack("<Q",  0x00000002))        # MiniDumpWithFullMemory

        for stype, dsz, srva in stream_dir:
            buf.write(struct.pack("<III", stype, dsz, srva))

        with open(path, "wb") as fh:
            fh.write(buf.getvalue())

    def _pack_sysinfo(self):
        """MINIDUMP_SYSTEM_INFO (56 bytes)."""
        d  = struct.pack("<H", self.arch)
        d += struct.pack("<H", 6)                   # ProcessorLevel
        d += struct.pack("<H", 0)                   # ProcessorRevision
        d += struct.pack("<B", self.n_cpus)
        d += struct.pack("<B", 1)                   # ProductType (Workstation)
        d += struct.pack("<I", self.os_major)
        d += struct.pack("<I", self.os_minor)
        d += struct.pack("<I", self.os_build)
        d += struct.pack("<I", PLATFORM_WIN32_NT)
        d += struct.pack("<I", 0)                   # CSDVersionRva
        d += struct.pack("<H", 0)                   # SuiteMask
        d += struct.pack("<H", 0)                   # Reserved2
        d += b"\x00" * 24                           # CPU_INFORMATION
        return d

    def _pack_modules(self, name_rvas):
        """MINIDUMP_MODULE_LIST."""
        d = struct.pack("<I", len(self.modules))
        for i, (_, base, size, ts) in enumerate(self.modules):
            d += struct.pack("<Q", base)            # BaseOfImage
            d += struct.pack("<I", size)            # SizeOfImage
            d += struct.pack("<I", 0)               # CheckSum
            d += struct.pack("<I", ts)              # TimeDateStamp
            d += struct.pack("<I", name_rvas[i])    # ModuleNameRva
            d += b"\x00" * 52                       # VS_FIXEDFILEINFO
            d += struct.pack("<II", 0, 0)           # CvRecord
            d += struct.pack("<II", 0, 0)           # MiscRecord
            d += struct.pack("<QQ", 0, 0)           # Reserved
        return d


# ══════════════════════════════════════════════════════════════════════
# Volatility3 CLI bridge
# ══════════════════════════════════════════════════════════════════════

def _run_vol(vol_cmd, dump_path, plugin, extra_args=None):
    """Run a vol3 plugin and return its stdout."""
    cmd = [vol_cmd, "-f", str(dump_path), "-q"]
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(plugin)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 and r.stderr.strip():
        print(f"  [vol3] {r.stderr.strip()[:200]}", file=sys.stderr)
    return r.stdout


def vol3_find_lsass(vol_cmd, dump_path):
    """Return the LSASS PID from the crash dump."""
    out = _run_vol(vol_cmd, dump_path, "windows.pslist.PsList")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2].lower() == "lsass.exe":
            return int(parts[0])
    return None


def vol3_system_info(vol_cmd, dump_path):
    """Return (is_64bit, major, minor, build) from the crash dump."""
    out = _run_vol(vol_cmd, dump_path, "windows.info.Info")
    info = {}
    for line in out.splitlines():
        if "\t" in line:
            key, _, val = line.partition("\t")
            info[key.strip()] = val.strip()

    is64   = info.get("Is64Bit", "True").lower() == "true"
    major  = int(info.get("NtMajorVersion", "10"))
    minor  = int(info.get("NtMinorVersion", "0"))
    build_lab = info.get("NtBuildLab", "19041")
    build  = int(re.match(r"(\d+)", build_lab).group(1))
    return is64, major, minor, build


def vol3_lsass_modules(vol_cmd, dump_path, pid):
    """Return [(name, base_addr, size)] for LSASS modules."""
    out = _run_vol(vol_cmd, dump_path, "windows.dlllist.DllList",
                   ["--pid", str(pid)])
    modules = []
    for line in out.splitlines():
        parts = line.split("\t") if "\t" in line else line.split()
        if not parts or not parts[0].isdigit():
            continue
        try:
            base = int(parts[2], 16) if parts[2].startswith("0x") else int(parts[2])
            size = int(parts[3], 16) if parts[3].startswith("0x") else int(parts[3])
            name = parts[4] if len(parts) > 4 else "unknown"
            path = parts[5] if len(parts) > 5 else name
            modules.append((path, base, size))
        except (ValueError, IndexError):
            continue
    return modules


def vol3_dump_lsass_memory(vol_cmd, dump_path, pid, output_dir):
    """Dump LSASS memory regions via vol3 memmap.

    Returns (regions, raw_path).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    out = _run_vol(vol_cmd, dump_path, "windows.memmap.Memmap",
                   ["--pid", str(pid), "--dump", "-o", str(output_dir)])

    regions = []
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            vaddr = int(parts[0], 16)
            size  = int(parts[2], 16)
            regions.append((vaddr, size))
        except (ValueError, IndexError):
            continue

    raw_path = output_dir / f"pid.{pid}.dmp"
    if not raw_path.exists():
        for f in output_dir.glob(f"*{pid}*"):
            raw_path = f
            break

    return regions, raw_path


# ══════════════════════════════════════════════════════════════════════
# Main extraction pipeline
# ══════════════════════════════════════════════════════════════════════

def extract_from_crashdump(
    dump_path,
    output_dir,
    vol_cmd="vol",
    pypykatz_cmd="pypykatz",
    kerberos_dir=None,
):
    """Full pipeline: crash dump → LSASS minidump → pypykatz → credentials.

    Returns (results_text, n_kirbi).
    """
    dump_path  = Path(dump_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: system info ──
    print("[*] Reading system info from crash dump ...")
    is64, os_major, os_minor, os_build = vol3_system_info(vol_cmd, dump_path)
    arch = ARCH_AMD64 if is64 else ARCH_INTEL
    print(f"    Windows {os_major}.{os_minor} build {os_build} ({'x64' if is64 else 'x86'})")

    # ── Step 2: find LSASS ──
    print("[*] Locating LSASS process ...")
    pid = vol3_find_lsass(vol_cmd, dump_path)
    if pid is None:
        print("[!] LSASS not found in crash dump", file=sys.stderr)
        return None, 0
    print(f"    LSASS PID: {pid}")

    # ── Step 3: module list ──
    print("[*] Enumerating LSASS modules ...")
    modules_raw = vol3_lsass_modules(vol_cmd, dump_path, pid)
    print(f"    {len(modules_raw)} modules found")

    # ── Step 4: dump LSASS memory ──
    print("[*] Dumping LSASS virtual memory (this may take a while) ...")
    work_dir = output_dir / "vol3_work"
    regions, raw_path = vol3_dump_lsass_memory(vol_cmd, dump_path, pid, work_dir)
    if not raw_path.exists():
        print("[!] vol3 memory dump not found", file=sys.stderr)
        return None, 0
    total_mb = raw_path.stat().st_size / 1048576
    print(f"    {len(regions)} regions, {total_mb:.0f} MB total")

    # ── Step 5: read PE timestamps from dumped memory ──
    print("[*] Reading PE timestamps from module headers ...")
    addr_space = VirtualAddressSpace(regions, raw_path)
    modules = []
    for path, base, size in modules_raw:
        ts = pe_timestamp(addr_space, base)
        modules.append((path, base, size, ts))

    # ── Step 6: build LSASS minidump ──
    print("[*] Building LSASS minidump ...")
    builder = MinidumpBuilder()
    builder.set_sysinfo(arch, os_major, os_minor, os_build)

    for path, base, size, ts in modules:
        builder.add_module(path, base, size, ts)

    for vaddr, data in addr_space.read_all_regions():
        builder.add_region(vaddr, data)

    minidump_path = output_dir / "lsass.dmp"
    builder.write(str(minidump_path))
    mini_mb = minidump_path.stat().st_size / 1048576
    print(f"    Minidump written: {minidump_path} ({mini_mb:.0f} MB)")

    # ── Step 7: pypykatz ──
    print("[*] Running pypykatz on LSASS minidump ...")
    cmd = [pypykatz_cmd, "lsa", "minidump", str(minidump_path)]
    if kerberos_dir:
        kerberos_dir = Path(kerberos_dir)
        kerberos_dir.mkdir(parents=True, exist_ok=True)
        cmd.extend(["-k", str(kerberos_dir)])

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[!] pypykatz error: {result.stderr.strip()[:300]}", file=sys.stderr)

    n_kirbi = 0
    if kerberos_dir:
        n_kirbi = len(list(Path(kerberos_dir).glob("*.kirbi")))

    return result.stdout, n_kirbi


# ══════════════════════════════════════════════════════════════════════
# CLI — standalone usage: lsass-extract <dump> -o <output>
# ══════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description="Extract LSASS credentials from a Windows crash dump (Linux)"
    )
    p.add_argument("dump", help="Path to the crash dump (.dmp)")
    p.add_argument("-o", "--output", default="./forensike_out",
                   help="Output directory (default: ./forensike_out)")
    p.add_argument("-k", "--kerberos-dir", default=None,
                   help="Export .kirbi tickets to this directory")
    p.add_argument("--vol", default="vol",
                   help="Volatility3 command (default: vol)")
    p.add_argument("--pypykatz", default="pypykatz",
                   help="pypykatz command (default: pypykatz)")
    args = p.parse_args()

    text, n_kirbi = extract_from_crashdump(
        args.dump, args.output,
        vol_cmd=args.vol,
        pypykatz_cmd=args.pypykatz,
        kerberos_dir=args.kerberos_dir,
    )

    if text:
        results_path = Path(args.output) / "forensike_results.txt"
        with open(results_path, "w") as f:
            f.write(text)
        print(f"\n[+] Results → {results_path}")
        if n_kirbi:
            print(f"[+] {n_kirbi} Kerberos ticket(s) → {args.kerberos_dir}")
    else:
        print("[!] Extraction failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
