# Forensike

Forensike is a Powershell script that leverages a RAM acquisition tool (DumpIt from MAGNET Forensics) in order to generate a Windows Crash Dump on a compromised host. Once you get your hands on a domain user that has local admin rights over a machine you can reach, you can start a Powershell session from which you will launch Forensike (you can use the `runas` command or (Over)Pass-The-Hash with classic tool if you don't have the cleartext password).

The script will then connect to the machine to retrieve some info about it that will help you with the rest of the attack. After validating, Forensike will transfer the RAM acquisition tool, create a Windows Crash dump, and execute a WinDBG session that will use the mimilib.dll extension to remotely extract LSASS.exe memory from the Crash Dump (crash dump always remains on the target disk)

This tool combines WMI queries, forensics and debugging techniques to extract NT hashes from the target LSASS process without directly reading LSASS memory.

Forensike guides you by giving you the space available on the target so that you don't saturate its disk as well as the current logged in user so that you know if the target is worth dumping its RAM.

At the time of writing, I have not encountered a specific EDR technology that has a default policy against the generation of Windows Crash dumps. As creating a Windows Crash dump is mostly part of a legitimate forensics behavior, the EDR I have worked against in my engagements and personal tests never blocked the writing of DumpIt on the target's disk nor the generation of final crash dump file. Like many other RAM acquisition tools, the driver used to access physical memory is signed, preventing EDRs from blocking them as soon as they start acquiring memory. I like to consider this attack as an extension of BYOVD attacks (Bring Your Own Vulnerable Driver)

Here is a demo : https://youtu.be/THuil2RaqJY

If you want more details about the tool or Forensics techniques applied for offensive security : you can check this article I wrote : https://publish.obsidian.md/yooga-sec/Forensike%2C+or+Forensics+for+bad+guys

## Installation

- Main installation is WinDBG on your system : https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
- The script directly calls the WinDBG executable, so it needs to be accessible from anywhere on your system. So make sure that the WinDBG executable you use is in your PATH !

## Usage :

- Launch the Forensike.ps1 script from a Powershell session that has local admin rights over the target
- `target` : Give it a target. Only takes a netbios name. If you have DNS troubles in the environment you are working in, just add the target name and IP in your hosts file, the tool will retrieve the IP this way
- `toolsDir` : Specify the folder in which you put your DumpIt executable so that Forensike can transfer it on the target and initiates Crash Dump generation
- `toolsDir` : Specify the folder in which you want to write the `forensike_results.txt` with parsed hashes. The script also provides you with 2 files `lsass.txt` which contains the LSASS EPROCESS address in the crash dump you will generate and the `hashes.txt` which is the raw output of mimilib.dll. If the script did not properly quit or if you need to debug it, these 2 files can help you.
- The script uses WMI queries to retrieve some information
- Disk space Estimation : The script roughly calculates how large the final crash dump will be on the target system and tell you how much space remains on target's C:\, so you know if there is have enough space to welcome the crash dump before lauching the attack

Enjoy !


TO DO :

- Kerberos ticket dumping
- Check if other disks exist on the target and how much space left (✅)
- EDR detection
- 
