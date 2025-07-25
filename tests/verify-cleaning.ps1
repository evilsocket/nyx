#!/usr/bin/env pwsh
# verify-cleaning.ps1 - Comprehensive verification script for Nyx cleaning effectiveness
# Verifies all artifacts created by create-artifacts.ps1 have been properly cleaned

param(
    [switch]$Verbose,
    [switch]$Summary
)

# Color output functions
function Write-Success {
    param([string]$Message)
    if ($Host.UI.SupportsVirtualTerminal) {
        Write-Host "[✓] $Message" -ForegroundColor Green
    } else {
        Write-Host "[✓] $Message"
    }
}

function Write-Failure {
    param([string]$Message)
    if ($Host.UI.SupportsVirtualTerminal) {
        Write-Host "[✗] $Message" -ForegroundColor Red
    } else {
        Write-Host "[✗] $Message"
    }
}

function Write-Info {
    param([string]$Message)
    if ($Host.UI.SupportsVirtualTerminal) {
        Write-Host "[i] $Message" -ForegroundColor Blue
    } else {
        Write-Host "[i] $Message"
    }
}

# Global counters
$script:PassedTests = 0
$script:FailedTests = 0
$script:TotalTests = 0

function Test-Artifact {
    param(
        [string]$TestName,
        [bool]$ArtifactExists,
        [string]$Details = ""
    )
    
    $script:TotalTests++
    
    if (-not $ArtifactExists) {
        $script:PassedTests++
        if ($Verbose) {
            $msg = "$TestName - CLEANED"
            if ($Details) { $msg += " ($Details)" }
            Write-Success $msg
        }
        return $true
    } else {
        $script:FailedTests++
        $msg = "$TestName - STILL EXISTS"
        if ($Details) { $msg += " ($Details)" }
        Write-Failure $msg
        return $false
    }
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "        Nyx Cleaning Verification Report" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# 1. PowerShell History
Write-Info "Checking PowerShell history..."
$histPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
$psHistoryExists = $false
if (Test-Path $histPath) {
    $content = Get-Content $histPath -ErrorAction SilentlyContinue
    $psHistoryExists = ($content -match "NYX-WIN-TEST").Count -gt 0
}
Test-Artifact "PowerShell History (NYX-WIN-TEST)" $psHistoryExists $histPath

# 2. Jump-list shortcut
Write-Info "Checking Recent folder (.lnk files)..."
$lnkPath = "$env:APPDATA\Microsoft\Windows\Recent\nyx-test.lnk"
$lnkExists = Test-Path $lnkPath
Test-Artifact "Jump List Shortcut" $lnkExists $lnkPath

# 3. Event log marker
Write-Info "Checking NYXTEST event logs..."
$eventsExist = $false
try {
    $events = Get-EventLog -LogName Application -Source "NYXTEST" -Newest 1 -ErrorAction SilentlyContinue
    $eventsExist = $events.Count -gt 0
} catch {
    $eventsExist = $false
}
Test-Artifact "NYXTEST Event Log Entries" $eventsExist "Application Log"

# 4. Prefetch files
Write-Info "Checking prefetch files..."
$prefetchExists = $false
$prefetchFiles = Get-ChildItem "C:\Windows\Prefetch\NOTEPAD*.pf" -ErrorAction SilentlyContinue
$prefetchExists = $prefetchFiles.Count -gt 0
Test-Artifact "NOTEPAD Prefetch Files" $prefetchExists "C:\Windows\Prefetch\"

# 5. Windows Timeline/Activity History
Write-Info "Checking Windows Timeline/Activity History..."
$activityPath = "$env:LOCALAPPDATA\ConnectedDevicesPlatform\nyx-test-activity.db"
$timelineExists = Test-Path $activityPath
Test-Artifact "Windows Timeline Activity" $timelineExists $activityPath

# 6. Windows Search History
Write-Info "Checking Windows Search History..."
$searchPath = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\nyx-search-test.txt"
$searchExists = Test-Path $searchPath
Test-Artifact "Windows Search History" $searchExists $searchPath

# 7. Internet Explorer History
Write-Info "Checking Internet Explorer History..."
$iePath = "$env:LOCALAPPDATA\Microsoft\Windows\History\nyx-ie-test.txt"
$ieExists = Test-Path $iePath
Test-Artifact "Internet Explorer History" $ieExists $iePath

# 8. Edge Legacy artifacts
Write-Info "Checking Edge Legacy artifacts..."
$edgePath = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\nyx-edge-test.txt"
$edgeExists = Test-Path $edgePath
Test-Artifact "Edge Legacy Artifacts" $edgeExists $edgePath

# 9. Network credentials
Write-Info "Checking Network credentials..."
$credsExist = $false
try {
    $creds = cmdkey /list 2>$null | Select-String "NYX-TEST-SERVER"
    $credsExist = $creds.Count -gt 0
} catch {
    $credsExist = $false
}
Test-Artifact "Network Credentials (NYX-TEST-SERVER)" $credsExist "cmdkey store"

# 10. Windows Defender history
Write-Info "Checking Windows Defender history..."
$defenderPath = "C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\nyx-defender-test.txt"
$defenderExists = Test-Path $defenderPath
Test-Artifact "Windows Defender History" $defenderExists $defenderPath

# 11. Cortana history
Write-Info "Checking Cortana history..."
$cortanaPath = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\LocalState\nyx-cortana-test.txt"
$cortanaExists = Test-Path $cortanaPath
Test-Artifact "Cortana History" $cortanaExists $cortanaPath

# 12. Windows Terminal/Console MRU
Write-Info "Checking Windows Terminal MRU settings..."
$terminalMruExists = $false
try {
    $bufferSize = Get-ItemProperty -Path 'HKCU:\Console' -Name 'HistoryBufferSize' -ErrorAction SilentlyContinue
    $numBuffers = Get-ItemProperty -Path 'HKCU:\Console' -Name 'NumberOfHistoryBuffers' -ErrorAction SilentlyContinue
    $terminalMruExists = ($bufferSize -ne $null) -or ($numBuffers -ne $null)
} catch {
    $terminalMruExists = $false
}
Test-Artifact "Windows Terminal MRU Settings" $terminalMruExists "HKCU:\Console"

# 13. Remote Desktop Connection history
Write-Info "Checking RDP connection history..."
$rdpExists = $false
try {
    $rdpMru = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Terminal Server Client\Default' -Name 'MRU0' -ErrorAction SilentlyContinue
    $rdpExists = ($rdpMru -ne $null) -and ($rdpMru.MRU0 -eq 'NYX-TEST-RDP-SERVER')
} catch {
    $rdpExists = $false
}
Test-Artifact "RDP Connection History" $rdpExists "HKCU:\Software\Microsoft\Terminal Server Client\Default"

# 14. Windows Media Player history
Write-Info "Checking Windows Media Player history..."
$wmpExists = $false
try {
    $wmpHistory = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\MediaPlayer\Player\RecentFileList' -Name 'File0' -ErrorAction SilentlyContinue
    $wmpExists = ($wmpHistory -ne $null) -and ($wmpHistory.File0 -eq 'C:\NYX-TEST-MEDIA.mp3')
} catch {
    $wmpExists = $false
}
Test-Artifact "Windows Media Player History" $wmpExists "HKCU:\Software\Microsoft\MediaPlayer\Player\RecentFileList"

# 15. Windows Notification history
Write-Info "Checking Windows Notification history..."
$notifPath = "$env:LOCALAPPDATA\Microsoft\Windows\Notifications\nyx-notif-test.txt"
$notifExists = Test-Path $notifPath
Test-Artifact "Windows Notification History" $notifExists $notifPath

# 16. Recycle Bin check (general)
Write-Info "Checking Recycle Bin contents..."
$recycleBinHasContent = $false
try {
    $recycleBinContent = Get-ChildItem "C:\`$Recycle.Bin" -Force -ErrorAction SilentlyContinue
    $recycleBinHasContent = ($recycleBinContent | Where-Object { $_.Name -ne "desktop.ini" }).Count -gt 0
} catch {
    $recycleBinHasContent = $false
}
Test-Artifact "Recycle Bin Contents" $recycleBinHasContent "C:\`$Recycle.Bin"

# 17. Registry MRU cleanup verification
Write-Info "Checking common MRU registry keys..."
$mruExists = $false
$mruKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
)

foreach ($key in $mruKeys) {
    if (Test-Path $key) {
        $items = Get-ChildItem $key -ErrorAction SilentlyContinue
        if ($items.Count -gt 0) {
            $mruExists = $true
            break
        }
    }
}
Test-Artifact "Registry MRU Keys" $mruExists "Explorer MRUs"

# 18. Chromium Edge History
Write-Info "Checking Chromium Edge History..."
$edgeChromDb = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
$edgeChromExists = Test-Path $edgeChromDb
Test-Artifact "Edge (Chromium) History Database" $edgeChromExists $edgeChromDb

# 19. Thumbs.db legacy files
Write-Info "Checking for Thumbs.db files..."
$thumbsExists = $false
try {
    $thumbsFiles = Get-ChildItem -Path $env:USERPROFILE -Include Thumbs.db -Recurse -ErrorAction SilentlyContinue
    $thumbsExists = $thumbsFiles.Count -gt 0
} catch {
    $thumbsExists = $false
}
Test-Artifact "Legacy Thumbs.db Files" $thumbsExists "$env:USERPROFILE (recursive)"

# 20. Thumbnail cache
Write-Info "Checking thumbnail cache..."
$thumbCacheExists = $false
$thumbPath = "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db"
$thumbCacheFiles = Get-ChildItem $thumbPath -ErrorAction SilentlyContinue
$thumbCacheExists = $thumbCacheFiles.Count -gt 0
Test-Artifact "Thumbnail Cache Files" $thumbCacheExists "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Explorer\"

# 21. Security Event Logs
Write-Info "Checking Security Event Logs..."
$securityEventsExist = $false
try {
    $secEvents = Get-EventLog -LogName Security -Newest 10 -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*NYX-SECURITY-TEST*" }
    $securityEventsExist = $secEvents.Count -gt 0
} catch {
    $securityEventsExist = $false
}
Test-Artifact "Security Event Logs (NYX-SECURITY-TEST)" $securityEventsExist "Security Log"

# 22. Sysmon logs
Write-Info "Checking Sysmon logs..."
$sysmonExists = $false
if (Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue) {
    try {
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"} -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*NYX-SYSMON-TEST*" }
        $sysmonExists = $sysmonEvents.Count -gt 0
    } catch {
        $sysmonExists = $false
    }
}
Test-Artifact "Sysmon Logs" $sysmonExists "Microsoft-Windows-Sysmon/Operational"

# 23. Windows Defender ATP
Write-Info "Checking Windows Defender ATP..."
$atpPath = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Cache\nyx-atp-test.dat"
$atpExists = Test-Path $atpPath
Test-Artifact "Windows Defender ATP Cache" $atpExists $atpPath

# 24. Windows Firewall logs
Write-Info "Checking Windows Firewall logs..."
$fwLogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
$fwLogExists = $false
if (Test-Path $fwLogPath) {
    $content = Get-Content $fwLogPath -ErrorAction SilentlyContinue
    $fwLogExists = ($content -match "NYX-FIREWALL-TEST").Count -gt 0
}
Test-Artifact "Windows Firewall Logs" $fwLogExists $fwLogPath

# 25. WMI Activity logs
Write-Info "Checking WMI Activity logs..."
$wmiLogPath = "$env:WINDIR\System32\wbem\Logs\wmi-activity.log"
$wmiLogExists = $false
if (Test-Path $wmiLogPath) {
    $content = Get-Content $wmiLogPath -ErrorAction SilentlyContinue
    $wmiLogExists = ($content -match "NYX-WMI-TEST").Count -gt 0
}
Test-Artifact "WMI Activity Logs" $wmiLogExists $wmiLogPath

# 26. USB device history (enhanced)
Write-Info "Checking USB device history..."
$usbExists = $false
try {
    $usbKey = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*' -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -like "*NYX-USB-TEST*" }
    $usbExists = $usbKey -ne $null
} catch {
    $usbExists = $false
}
Test-Artifact "USB Device History (NYX-USB-TEST)" $usbExists "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"

# 27. BitLocker recovery keys
Write-Info "Checking BitLocker recovery keys..."
$bitlockerPath = "$env:TEMP\BitLockerRecoveryKeys\nyx-recovery.txt"
$bitlockerExists = Test-Path $bitlockerPath
Test-Artifact "BitLocker Recovery Keys" $bitlockerExists $bitlockerPath

# 28. Certificate stores
Write-Info "Checking Certificate stores..."
$certExists = $false
try {
    $cert = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like "*NYX-TEST-CERT*" }
    $certExists = $cert -ne $null
} catch {
    $certExists = $false
}
Test-Artifact "Certificate Store (NYX-TEST-CERT)" $certExists "Cert:\CurrentUser\My"

# 29. Group Policy history
Write-Info "Checking Group Policy history..."
$gpPath = "$env:WINDIR\System32\GroupPolicy\DataStore\nyx-gp-test.xml"
$gpExists = Test-Path $gpPath
Test-Artifact "Group Policy History" $gpExists $gpPath

# 30. Scheduled Tasks
Write-Info "Checking Scheduled Tasks..."
$taskExists = $false
try {
    $task = Get-ScheduledTask -TaskName "NYX-TEST-TASK" -ErrorAction SilentlyContinue
    $taskExists = $task -ne $null
} catch {
    $taskExists = $false
}
Test-Artifact "Scheduled Task (NYX-TEST-TASK)" $taskExists "Task Scheduler"

# 31. Services
Write-Info "Checking Services..."
$serviceExists = $false
try {
    $service = Get-Service -Name "NYX-TEST-SERVICE" -ErrorAction SilentlyContinue
    $serviceExists = $service -ne $null
} catch {
    $serviceExists = $false
}
Test-Artifact "Service (NYX-TEST-SERVICE)" $serviceExists "Services"

# 32. Authentication logs
Write-Info "Checking Authentication logs..."
$authPath = "$env:WINDIR\System32\config\systemprofile\AppData\Local\Microsoft\Windows\SchCache\nyx-auth.dat"
$authExists = Test-Path $authPath
Test-Artifact "Authentication Logs" $authExists $authPath

# 33. Windows Update logs
Write-Info "Checking Windows Update logs..."
$wuLogPath = "$env:WINDIR\SoftwareDistribution\ReportingEvents.log"
$wuLogExists = $false
if (Test-Path $wuLogPath) {
    $content = Get-Content $wuLogPath -ErrorAction SilentlyContinue | Select-Object -Last 50
    $wuLogExists = ($content -match "NYX-WINDOWS-UPDATE-TEST").Count -gt 0
}
Test-Artifact "Windows Update Logs" $wuLogExists $wuLogPath

# 34. Wireless network profiles
Write-Info "Checking Wireless network profiles..."
$wifiExists = $false
try {
    $wifiProfiles = netsh wlan show profiles 2>$null | Select-String "NYX-TEST-WIFI"
    $wifiExists = $wifiProfiles.Count -gt 0
} catch {
    $wifiExists = $false
}
Test-Artifact "Wireless Network Profile (NYX-TEST-WIFI)" $wifiExists "WLAN Profiles"

# 35. VPN connections
Write-Info "Checking VPN connections..."
$vpnExists = $false
try {
    $vpn = Get-VpnConnection -Name "NYX-TEST-VPN" -ErrorAction SilentlyContinue
    $vpnExists = $vpn -ne $null
} catch {
    $vpnExists = $false
}
Test-Artifact "VPN Connection (NYX-TEST-VPN)" $vpnExists "VPN Connections"

# 36. Chrome extensions
Write-Info "Checking Chrome extensions..."
$chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\nyxtest123\manifest.json"
$chromeExtExists = Test-Path $chromeExtPath
Test-Artifact "Chrome Extension (NYX-TEST)" $chromeExtExists $chromeExtPath

# 37. Cryptographic provider logs
Write-Info "Checking Cryptographic provider logs..."
$cryptoPath = "$env:APPDATA\Microsoft\Crypto\RSA\nyx-crypto.dat"
$cryptoExists = Test-Path $cryptoPath
Test-Artifact "Cryptographic Provider Logs" $cryptoExists $cryptoPath

# 38. TPM logs
Write-Info "Checking TPM logs..."
$tpmLogPath = "$env:WINDIR\System32\wbem\Logs\tpm-events.log"
$tpmLogExists = $false
if (Test-Path $tpmLogPath) {
    $content = Get-Content $tpmLogPath -ErrorAction SilentlyContinue
    $tpmLogExists = ($content -match "NYX-TPM-TEST").Count -gt 0
}
Test-Artifact "TPM Logs" $tpmLogExists $tpmLogPath

# 39. Hyper-V logs
Write-Info "Checking Hyper-V logs..."
$hvLogPath = "C:\ProgramData\Microsoft\Windows\Hyper-V\Virtual Machines logs\nyx-vm.log"
$hvLogExists = Test-Path $hvLogPath
Test-Artifact "Hyper-V Logs" $hvLogExists $hvLogPath

# 40. WSL logs
Write-Info "Checking WSL logs..."
$wslLogPath = "$env:LOCALAPPDATA\Packages\CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc\LocalState\ext4.vhdx.log"
$wslLogExists = Test-Path $wslLogPath
Test-Artifact "WSL Logs" $wslLogExists $wslLogPath

# 41. Docker Desktop logs
Write-Info "Checking Docker Desktop logs..."
$dockerLogPath = "$env:APPDATA\Docker\log\docker-desktop.log"
$dockerLogExists = Test-Path $dockerLogPath
Test-Artifact "Docker Desktop Logs" $dockerLogExists $dockerLogPath

# 42. McAfee AV logs
Write-Info "Checking McAfee AV logs..."
$mcafeePath = "C:\ProgramData\McAfee\Endpoint Security\Logs\EndpointSecurityPlatform.log"
$mcafeeExists = Test-Path $mcafeePath
Test-Artifact "McAfee AV Logs" $mcafeeExists $mcafeePath

# 43. Symantec Endpoint Protection logs
Write-Info "Checking Symantec Endpoint Protection logs..."
$sepPath = "C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\AV\0.log"
$sepExists = Test-Path $sepPath
Test-Artifact "Symantec Endpoint Protection Logs" $sepExists $sepPath

# 44. CrowdStrike Falcon logs
Write-Info "Checking CrowdStrike Falcon logs..."
$csPath = "C:\ProgramData\CrowdStrike\Logs\FalconSensor.log"
$csExists = Test-Path $csPath
Test-Artifact "CrowdStrike Falcon Logs" $csExists $csPath

# 45. SentinelOne logs
Write-Info "Checking SentinelOne logs..."
$s1Path = "C:\ProgramData\Sentinel\Logs\SentinelAgent.log"
$s1Exists = Test-Path $s1Path
Test-Artifact "SentinelOne Logs" $s1Exists $s1Path

# 46. Carbon Black logs
Write-Info "Checking Carbon Black logs..."
$cbPath = "C:\ProgramData\CarbonBlack\Logs\cb.log"
$cbExists = Test-Path $cbPath
Test-Artifact "Carbon Black Logs" $cbExists $cbPath

# 47. FTK Imager artifacts
Write-Info "Checking FTK Imager artifacts..."
$ftkPath = "$env:APPDATA\AccessData\FTK Imager\RecentCases.xml"
$ftkExists = Test-Path $ftkPath
Test-Artifact "FTK Imager Artifacts" $ftkExists $ftkPath

# 48. Memory dumps
Write-Info "Checking Memory dumps..."
$memDumpPath = "C:\Windows\MEMORY.DMP"
$memDumpExists = $false
if (Test-Path $memDumpPath) {
    $content = Get-Content $memDumpPath -ErrorAction SilentlyContinue | Select-Object -First 10
    $memDumpExists = ($content -match "NYX-MEMORY-DUMP-TEST").Count -gt 0
}
Test-Artifact "Memory Dump" $memDumpExists $memDumpPath

# 49. Hibernation file traces
Write-Info "Checking Hibernation file traces..."
$hibPath = "$env:TEMP\HibernationTraces\hiberfil-analysis.txt"
$hibExists = Test-Path $hibPath
Test-Artifact "Hibernation File Traces" $hibExists $hibPath

# 50. Windows Error Reporting Queue (enhanced)
Write-Info "Checking Windows Error Reporting Queue..."
$werQueuePath = "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportQueue\NYX-TEST-CRASH\Report.wer"
$werQueueExists = Test-Path $werQueuePath
Test-Artifact "WER Queue (NYX-TEST-CRASH)" $werQueueExists $werQueuePath

# 51. SRUM database
Write-Info "Checking SRUM database..."
$srumPath = "C:\Windows\System32\sru\SRUDB.dat"
$srumExists = Test-Path $srumPath
Test-Artifact "SRUM Database" $srumExists $srumPath

# 52. Windows Push Notifications
Write-Info "Checking Windows Push Notifications..."
$wpnPath = "$env:LOCALAPPDATA\Microsoft\Windows\Notifications\wpndatabase.db-test.txt"
$wpnExists = Test-Path $wpnPath
Test-Artifact "Windows Push Notifications" $wpnExists $wpnPath

# 53. Office telemetry
Write-Info "Checking Office telemetry..."
$officeTelPath = "$env:LOCALAPPDATA\Microsoft\Office\16.0\Telemetry\nyx-telemetry.dat"
$officeTelExists = Test-Path $officeTelPath
Test-Artifact "Office Telemetry" $officeTelExists $officeTelPath

# 54. OneDrive logs
Write-Info "Checking OneDrive logs..."
$onedrivePath = "$env:LOCALAPPDATA\Microsoft\OneDrive\logs\SyncEngine.log"
$onedriveExists = Test-Path $onedrivePath
Test-Artifact "OneDrive Logs" $onedriveExists $onedrivePath

# 55. Teams logs
Write-Info "Checking Teams logs..."
$teamsPath = "$env:APPDATA\Microsoft\Teams\logs.txt"
$teamsExists = $false
if (Test-Path $teamsPath) {
    $content = Get-Content $teamsPath -ErrorAction SilentlyContinue
    $teamsExists = ($content -match "NYX-TEAMS-TEST").Count -gt 0
}
Test-Artifact "Teams Logs" $teamsExists $teamsPath

# 56. Outlook search history
Write-Info "Checking Outlook search history..."
$outlookPath = "$env:LOCALAPPDATA\Microsoft\Outlook\search-history.dat"
$outlookExists = Test-Path $outlookPath
Test-Artifact "Outlook Search History" $outlookExists $outlookPath

# 57. Windows Subsystem for Android logs
Write-Info "Checking Windows Subsystem for Android logs..."
$wsaPath = "$env:LOCALAPPDATA\Packages\MicrosoftCorporationII.WindowsSubsystemForAndroid_8wekyb3d8bbwe\LocalState\wsa.log"
$wsaExists = Test-Path $wsaPath
Test-Artifact "WSA Logs" $wsaExists $wsaPath

# 58. Xbox Game Bar
Write-Info "Checking Xbox Game Bar..."
$xboxPath = "$env:LOCALAPPDATA\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\LocalState\captures.log"
$xboxExists = Test-Path $xboxPath
Test-Artifact "Xbox Game Bar Logs" $xboxExists $xboxPath

# Summary Report
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "              VERIFICATION SUMMARY" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

$passRate = if ($script:TotalTests -gt 0) { [math]::Round(($script:PassedTests / $script:TotalTests) * 100, 2) } else { 0 }

Write-Host "Total Tests: $($script:TotalTests)"
if ($script:PassedTests -gt 0) {
    Write-Success "Passed (Cleaned): $($script:PassedTests)"
}
if ($script:FailedTests -gt 0) {
    Write-Failure "Failed (Still Exist): $($script:FailedTests)"
}
Write-Host "Success Rate: $passRate%" -ForegroundColor $(if ($passRate -eq 100) { 'Green' } elseif ($passRate -ge 80) { 'Yellow' } else { 'Red' })

Write-Host ""
if ($script:FailedTests -eq 0) {
    Write-Success "🎉 PERFECT CLEANING! All artifacts successfully removed."
} elseif ($script:FailedTests -le 2) {
    Write-Host "⚠️  GOOD CLEANING! Minor artifacts remain." -ForegroundColor Yellow
} else {
    Write-Failure "❌ CLEANING INCOMPLETE! Multiple artifacts remain."
}

Write-Host ""

# Exit with appropriate code
exit $script:FailedTests
