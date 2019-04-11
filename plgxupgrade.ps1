# param($url, $filename)

[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Globals
$url = 'https://github.com/polylogyx/osq-ext-bin/raw/master/plgx_win_extension.ext.exe'
$ExtnFilename = 'plgx_win_extension.ext.exe'

function DownloadExtensionBinary {   
    $webclient = New-Object System.Net.WebClient

    # $filename = 'plgx_win_extension.ext.exe'
    $filepath = "$pwd\$ExtnFilename"
   
    try {
        $webclient.DownloadFile($url, $filepath)       
    }
    catch [Net.WebException] {
        # Write-Host -ForegroundColor RED  $_.Exception.ToString()
        Write-Host -ForegroundColor RED "[-] Aborting Extension Upgrade, Failed to download extension binary from $url"
        Exit -1
    }

    Write-Host -ForegroundColor Yellow  "[+] Downloaded extension binary successfully: $ExtnFilename to $pwd"  
}

function StartOsqueryService {
    $ServiceName = 'osqueryd'
    $ServiceObj = Get-Service -Name $ServiceName

    Write-Host -ForegroundColor YELLOW '[+] Starting Osqueryd Service'
    Start-Service -Name $ServiceName

    Start-Sleep(3)
    $ServiceObj.Refresh()
    Write-Host -ForegroundColor YELLOW '[+] Osqueryd Service Status: ' $ServiceObj.Status   
}


function StopOsqueryService {

    $ServiceName = 'osqueryd'
    $ServiceObj = Get-Service -Name $ServiceName

    if ($ServiceObj.Status -eq 'Running') {
        Stop-Service $ServiceName  -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Yellow '[+] Osqueryd Service Status: '  $ServiceObj.status
        Write-Host -ForegroundColor Yellow '[+] Osqueryd Service Stop Initiated...Wait for service to stop'

        Start-Sleep -Seconds 10
        $ServiceObj.Refresh()       
    }    

    # fetch osqueryd and extension process object to terminate forcefully if they survive
    $OsquerydProc = Get-Process osqueryd -ErrorAction SilentlyContinue
    $PlgxExtnProc = Get-Process plgx_win_extension.ext.exe -ErrorAction SilentlyContinue
    
    if ($ServiceObj.Status -ne 'Stopped' -Or $OsquerydProc -Or $PlgxExtnProc) {
        Write-Host -ForegroundColor Yellow '[+] Force kill osqueryd and extension process if still exist'

        if ($OsquerydProc) {
            Stop-Process -Name 'osqueryd' -Force -ErrorAction SilentlyContinue
        }

        if($PlgxExtnProc)
        {
            Stop-Process -Name 'plgx_win_extension.ext' -Force -ErrorAction SilentlyContinue
        }
    }   
    Write-Host -ForegroundColor Yellow '[+] Osqueryd Service Stopped'
}


function StopPlgxServices {
    # clean vast service
    $VastSvc = 'vast'
    $VastPath = "$Env:windir\system32\drivers\vast.sys"    
    $ServiceObj = Get-Service -Name $VastSvc    
    
    if ($ServiceObj.Status -eq 'Running') {
        Stop-Service $VastSvc  -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Yellow '[+] VAST Service Status: ' $ServiceObj.status
        Write-Host -ForegroundColor Yellow '[+] VAST Service Stop Initiated...Wait for service to stop'
        
        $WaitRetryCount = 0
    
        while ($ServiceObj.Status -ne 'Stopped' -and $WaitRetryCount -le 3) {
            Start-Sleep -Seconds 10
            $ServiceObj.Refresh()
            Write-Host -ForegroundColor Yellow '[+] VAST Service Status: ' $ServiceObj.status
            $WaitRetryCount += 1
            Write-Host -ForegroundColor Yellow  '[+] VAST Service Stop Wait Retry Count : ' $WaitRetryCount
        }
    
    }
    Write-Host -ForegroundColor Yellow '[+] VAST Service is now Stopped or timed-out, cleanup vast.sys'
    Remove-Item -Path $VastPath -Force -ErrorAction SilentlyContinue
        
    # clean vastnw service
    $VastnwSvc = 'vastnw'
    $VastnwPath = "$Env:windir\system32\drivers\vastnw.sys"
    $ServiceObj = Get-Service -Name $VastnwSvc  

    if ($ServiceObj.Status -eq 'Running') {
        Stop-Service $VastnwSvc  -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Yellow '[+] VASTNW Service Status: ' $ServiceObj.status
        Write-Host -ForegroundColor Yellow '[+] VASTNW Service Stop Initiated...Wait for service to stop'
        
        $WaitRetryCount = 0
        while ($ServiceObj.Status -ne 'Stopped' -and $WaitRetryCount -le 3) {
            Start-Sleep -Seconds 10
            $ServiceObj.Refresh()
            Write-Host -ForegroundColor Yellow '[+] VASTNW Service Status: ' $ServiceObj.status
            $WaitRetryCount += 1
            Write-Host -ForegroundColor Yellow  '[+] VASTNW Service Stop Wait Retry Count '  $WaitRetryCount
        }    
    }
    Write-Host -ForegroundColor Yellow '[+] VASTNW service is now Stopped or timed-out, cleanup vastnw.sys'
    Remove-Item -Path $VastnwPath -Force -ErrorAction SilentlyContinue
}

# Adapted from http://www.jonathanmedd.net/2014/01/testing-for-admin-privileges-in-powershell.html
function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator"
    )
}
  
function Main {
    Write-Host -ForegroundColor YELLOW  "============ Polylogyx Helper Script to upgrade extension. ============"

    Write-Host "[+] Verifying script is running with Admin privileges" -foregroundcolor Yellow
    if (-not (Test-IsAdmin)) {
        Write-Host "[-] ERROR: Please run this script with Admin privileges!" -foregroundcolor Red
        Exit -1
    }

    # Download extension binary, stop osqueryd, vast and vastnw service before updating.
    DownloadExtensionBinary
    StopOsqueryService
    StopPlgxServices

    # Update downloaded extension binary and restart osqueryd service
    $dstpath = "$Env:Programdata\osquery\$extn"
    Write-Host -ForegroundColor Yellow "[+] Copying downloaded extension binary to default osquery install location."
    Copy-Item -Path "$pwd\$ExtnFilename" -Destination $dstpath -Force

    StartOsqueryService
    Write-Host -ForegroundColor Yellow '[+] Extension SuccessFully Updated, Please Check osqueryd/vast services.'
    Write-Host -ForegroundColor Yellow "========================================================================"
}

$startTime = Get-Date
$null = Main
$endTime = Get-Date
Write-Host "[+] Extension Update took $(($endTime - $startTime).TotalSeconds) seconds."