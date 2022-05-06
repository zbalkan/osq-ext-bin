param(
  [switch] $help = $false,
  [switch] $evtlog = $false,
  [switch] $fslog = $false
)

[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Globals
$extnDownloadUrl = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/plgx_win_extension.ext.exe'
$osquerydDownloadUrl = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/osqueryd.exe'
$osqueryConfDownloadUrl = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/osquery.conf'
$osqueryEvtloggerFlagsDownloadUrl = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/osquery_evtlogger.flags'
$osqueryFsloggerFlagsDownloadUrl = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/osquery_fslogger.flags'
$osqueryManifestDownloadUrl = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/osquery.man'

# Globals for packs files
$osqueryPack1Url = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/packs/hardware-monitoring.conf'
$osqueryPack2Url = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/packs/incident-response.conf'
$osqueryPack3Url = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/packs/it-compliance.conf'
$osqueryPack4Url = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/packs/osquery-monitoring.conf'
$osqueryPack5Url = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/packs/ossec-rootkit.conf'
$osqueryPack6Url = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/packs/osx-attacks.conf'
$osqueryPack7Url = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/packs/unwanted-chrome-extensions.conf'
$osqueryPack8Url = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/packs/vuln-management.conf'
$osqueryPack9Url = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/packs/windows-attacks.conf'
$osqueryPack10Url = 'https://github.com/eclecticiq/osq-ext-bin/raw/master/osquery/packs/windows-hardening.conf'


$ExtnFilename = 'plgx_win_extension.ext.exe'
$OsquerydFilename = 'osqueryd.exe'
$OsqueryConfFilename = 'osquery.conf'
$OsqueryEvtloggerFlagsFilename = 'osquery_evtlogger.flags'
$OsqueryFsloggerFlagsFilename = 'osquery_fslogger.flags'
$OsqueryManifestFilename = 'osquery.man'
$OsqueryPackFile1 = 'hardware-monitoring.conf'
$OsqueryPackFile2 = 'incident-response.conf'
$OsqueryPackFile3 = 'it-compliance.conf'
$OsqueryPackFile4 = 'osquery-monitoring.conf'
$OsqueryPackFile5 = 'ossec-rootkit.conf'
$OsqueryPackFile6 = 'osx-attacks.conf'
$OsqueryPackFile7 = 'unwanted-chrome-extensions.conf'
$OsqueryPackFile8 = 'vuln-management.conf'
$OsqueryPackFile9 = 'windows-attacks.conf'
$OsqueryPackFile10 = 'windows-hardening.conf'


# osquery service variables
$kServiceName = "osqueryd"
$kServiceDescription = "osquery daemon service"
$kServiceBinaryPath = (Join-Path "$Env:ProgramFiles\osquery\osqueryd\" "osqueryd.exe")
$welManifestPath = (Join-Path "$Env:ProgramFiles\osquery\" "osquery.man")

function DownloadFileFromUrl($fileDownloadUrl, $file)
{			
  $webclient = New-Object System.Net.WebClient
  $filepath = "$pwd\$file"

  try {
    $webclient.DownloadFile($fileDownloadUrl, $filepath)       
  }
  catch [Net.WebException] {
    Write-Host -ForegroundColor RED "[-] Aborting Extension Upgrade, Failed to download file from $fileDownloadUrl"
    Exit -1
  }

  Write-Host -ForegroundColor Yellow  "[+] Downloaded file successfully: $file to $pwd"
}

function DownloadFiles {
	DownloadFileFromUrl($extnDownloadUrl, $ExtnFilename)
	DownloadFileFromUrl($osquerydDownloadUrl, $OsquerydFilename)
	DownloadFileFromUrl($osqueryConfDownloadUrl, $OsqueryConfFilename)
	DownloadFileFromUrl($osqueryEvtloggerFlagsDownloadUrl, $OsqueryEvtloggerFlagsFilename)
	DownloadFileFromUrl($osqueryFsloggerFlagsDownloadUrl, $OsqueryFsloggerFlagsFilename)
	DownloadFileFromUrl($osqueryManifestDownloadUrl, $OsqueryManifestFilename)
	
	DownloadFileFromUrl($osqueryPack1Url, $OsqueryPackFile1)
	DownloadFileFromUrl($osqueryPack2Url, $OsqueryPackFile2)
	DownloadFileFromUrl($osqueryPack3Url, $OsqueryPackFile3)
	DownloadFileFromUrl($osqueryPack4Url, $OsqueryPackFile4)
	DownloadFileFromUrl($osqueryPack5Url, $OsqueryPackFile5)
	DownloadFileFromUrl($osqueryPack6Url, $OsqueryPackFile6)
	DownloadFileFromUrl($osqueryPack7Url, $OsqueryPackFile7)
	DownloadFileFromUrl($osqueryPack8Url, $OsqueryPackFile8)
	DownloadFileFromUrl($osqueryPack9Url, $OsqueryPackFile9)
	DownloadFileFromUrl($osqueryPack10Url, $OsqueryPackFile10)	
}

function StartOsqueryService {
	# install osquery service entry with manifest

	New-Service -BinaryPathName "$kServiceBinaryPath $startupArgs" `
				-Name $kServiceName `
				-DisplayName $kServiceName `
				-Description $kServiceDescription `
				-StartupType Automatic
	Write-Host "Installed '$kServiceName' system service." -foregroundcolor Cyan
	
	wevtutil im $welManifestPath
    if ($?) {
      Write-Host "The Windows Event Log manifest has been successfully installed." -foregroundcolor Cyan
    } else {
      Write-Host "Failed to install the Windows Event Log manifest." -foregroundcolor RED
    }

    $ServiceObj = Get-Service -Name $kServiceName

    Write-Host -ForegroundColor YELLOW '[+] Starting Osqueryd Service'
    Start-Service -Name $kServiceName

    Start-Sleep(3)
    $ServiceObj.Refresh()
    Write-Host -ForegroundColor YELLOW '[+] Osqueryd Service Status: ' $ServiceObj.Status 
}


function CheckOsqueryService {

	#check osqueryd service
    $ServiceName = 'osqueryd'
    $ServiceObj = Get-Service -Name $ServiceName

    if ($ServiceObj.Length -gt 0) {
        Write-Host -ForegroundColor Yellow '[+] Osqueryd Service Status: '  $ServiceObj.status
        Write-Host -ForegroundColor RED '[-] Osqueryd Service exists. Remove existing installation of osquery and try again. Script will abort the installation now!!'
        Exit -1
    } 
	else {
        Write-Host -ForegroundColor Yellow '[+] Osqueryd Service not found on the system: OK'
	}
}


function CheckEiqAgentService {

	#check EIQ agent service
    $ServiceName = 'plgx_agent'
    $ServiceObj = Get-Service -Name $ServiceName

    if ($ServiceObj.Length -gt 0) {
        Write-Host -ForegroundColor Yellow '[+] EIQ agent Service Status: '  $ServiceObj.status
        Write-Host -ForegroundColor RED '[-] EIQ agent Service exists. Remove existing installation of EIQ agent and try again. Script will abort the installation now!!'
        Exit -1
    }
	else {
        Write-Host -ForegroundColor Yellow '[+] EIQ agent Service not found on the system: OK'
	}	
}

# Adapted from http://www.jonathanmedd.net/2014/01/testing-for-admin-privileges-in-powershell.html
function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator"
    )
}

function CopyFile ($src, $dest) {
    Write-Host -ForegroundColor Yellow "[+] Copying $src to $dest."
    Copy-Item -Path "$src" -Destination "$dest" -Force
}

function CopyFilesToInstalldir {
	New-Item -Path '$Env:ProgramFiles\osquery\osqueryd' -ItemType Directory
	New-Item -Path '$Env:ProgramFiles\osquery\packs' -ItemType Directory
	
	CopyFile("$pwd\$ExtnFilename", "$Env:ProgramFiles\osquery\$ExtnFilename")
	CopyFile("$pwd\$OsquerydFilename", "$Env:ProgramFiles\osquery\osqueryd\$OsquerydFilename")
	CopyFile("$pwd\$OsqueryConfFilename", "$Env:ProgramFiles\osquery\$OsqueryConfFilename")
	
	#check what logger option was chosen for install then copy flags file accordingly
	if($evtlog){
		CopyFile("$pwd\$OsqueryEvtloggerFlagsFilename", "$Env:ProgramFiles\osquery\osquery.flags")
	} elseif($fslog) {
		CopyFile("$pwd\$OsqueryFsloggerFlagsFilename", "$Env:ProgramFiles\osquery\osquery.flags")
	} else {
		Write-Host -ForegroundColor RED '[-] We should not reach here. Script will abort the installation now!!'
        Exit -1
	}	
	
	CopyFile("$pwd\$OsqueryManifestFilename", "$Env:ProgramFiles\osquery\$OsqueryManifestFilename")	
	
	CopyFile("$pwd\$OsqueryPackFile1", "$Env:ProgramFiles\osquery\packs\$OsqueryPackFile1")
	CopyFile("$pwd\$OsqueryPackFile2", "$Env:ProgramFiles\osquery\packs\$OsqueryPackFile2")
	CopyFile("$pwd\$OsqueryPackFile3", "$Env:ProgramFiles\osquery\packs\$OsqueryPackFile3")
	CopyFile("$pwd\$OsqueryPackFile4", "$Env:ProgramFiles\osquery\packs\$OsqueryPackFile4")
	CopyFile("$pwd\$OsqueryPackFile5", "$Env:ProgramFiles\osquery\packs\$OsqueryPackFile5")
	CopyFile("$pwd\$OsqueryPackFile6", "$Env:ProgramFiles\osquery\packs\$OsqueryPackFile6")
	CopyFile("$pwd\$OsqueryPackFile7", "$Env:ProgramFiles\osquery\packs\$OsqueryPackFile7")
	CopyFile("$pwd\$OsqueryPackFile8", "$Env:ProgramFiles\osquery\packs\$OsqueryPackFile8")
	CopyFile("$pwd\$OsqueryPackFile9", "$Env:ProgramFiles\osquery\packs\$OsqueryPackFile9")
	CopyFile("$pwd\$OsqueryPackFile10", "$Env:ProgramFiles\osquery\packs\$OsqueryPackFile10")
}

function Do-Help {
  $programName = (Get-Item $PSCommandPath ).Name
  
  Write-Host "Usage: $programName (-evtlog|-fslog|-help)" -foregroundcolor Yellow
  Write-Host ""
  Write-Host "  Only one of the following options can be used. Using multiple will result in "
  Write-Host "  options being ignored."
  Write-Host "    -evtlog		Install the osqueryd service and extension with windows event log as the logger plugin"
  Write-Host "    -fslog		Install the osqueryd service and extension with filesystem as the logger plugin"
  Write-Host ""
  Write-Host "    -help		Shows this help screen"
  
  Exit 1
}


function Main {
    Write-Host -ForegroundColor YELLOW  "============ EclecticIQ Helper Script to install osquery with extension. ============"

    Write-Host "[+] Verifying script is running with Admin privileges" -foregroundcolor Yellow
    if (-not (Test-IsAdmin)) {
        Write-Host "[-] ERROR: Please run this script with Admin privileges!" -foregroundcolor Red
        Exit -1
    }

	if ($help) {
		Do-Help
	} elseif (($evtlog.ToBool() + $fslog.ToBool()) -Eq 1) {
		#verify osquery service doesnt exist
		CheckOsqueryService

		#verify EIQ agent service doesnt exist
		CheckEiqAgentService

		# Download all files
		DownloadFiles
		
		# Copy files to install location
		CopyFilesToInstalldir

		StartOsqueryService
		
		Write-Host -ForegroundColor Yellow "========================================================================"
	} else {
		Write-Host "Invalid option selected: please see -help for usage details." -foregroundcolor Red
		Exit -1
	}

}

$startTime = Get-Date
$null = Main
$endTime = Get-Date
Write-Host "[+] Extension Update took $(($endTime - $startTime).TotalSeconds) seconds."