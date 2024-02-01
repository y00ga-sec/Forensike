# Forensike

Forensike is a Powershell script that leverage a RAM acquisition tool (DumpIt from MAGNET Forensics) in order to generate a Windows Crash Dump on a compromised host. Once you get your hands on a domain user that has local admin rights over a machine you can reach, you can start a Powershell session from which you will launch Forensike (you can user the `runas` command or (Over)Pass-The-Hash with classic tool if you don't have the cleartext password).

The script will then connect to the machine to retrieve some info about it that will help you with the rest of the attack. After validating, Forensike will transfer the RAM acquisition tool, create a Windows Crash dump, and execute a WinDBG session that will use the mimilib.dll extension to remotely extract LSASS.exe memory from the Crash Dump (crash dump always remains on the target disk)

This tool combines WMI queries, forensics and debugging techniques to extract NT hashes from the target LSASS process without directly reading LSASS memory.

Forensike guides you by giving you the space available on the target so that you don't saturate its disk as well as the current logged in user so that you know if the target if worth dumping its RAM.

At the time of writing, I have not encountered a specific EDR technology that has a default policy against the generation of Windows Crash dumps. As creating a Windows Crash dump is mostly part of a legitimate forensics behavior, the EDR I have worked against in my engagements and personal tests never blocked the writing of DumpIt on the target's disk nor the generation of final crash dump file. Like many other RAM acquisition tools, the driver used to access physical memory is signed, preventing EDRs from blocking them as soon as they start acquiring memory. I like to consider this attack as an extension of BYOVD attacks (Bring Your Own Vulnerable Driver)

Here is a demo :

If you want more details about the tool or Forensics techniques applied for offensive security : you can check this article I wrote : 
