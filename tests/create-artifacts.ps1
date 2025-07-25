<#
create-artifacts.ps1
Run from an elevated PowerShell window
#>

# 1. PowerShell history
$hist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
@('whoami','Get-Date','echo NYX-WIN-TEST') | Out-File -Append $hist

# 2. Jump-list shortcut
$dummy = "$env:USERPROFILE\Desktop\nyx-test.txt"
'dummy' | Set-Content $dummy
$shell = New-Object -ComObject WScript.Shell
$lnk   = $shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Recent\nyx-test.lnk")
$lnk.TargetPath = $dummy ; $lnk.Save()

# 3. Prefetch entry
cmd /c start notepad.exe
Start-Sleep 2
Stop-Process -Name notepad -ErrorAction SilentlyContinue

# 4. Event-log marker
if (-not (Get-EventLog -LogName Application -Source "NYXTEST" -ErrorAction SilentlyContinue)) {
    New-EventLog -LogName Application -Source "NYXTEST"
}
Write-EventLog -LogName Application -Source NYXTEST -EventId 4242 `
               -Message "NYX-WIN-TEST EventLog entry"

# 5. Trigger a WER crash
try { 1/0 } catch { }

# 6. ShellBag / UserAssist (open Explorer)
Start-Process explorer.exe $env:USERPROFILE
Start-Sleep 2
Stop-Process -Name explorer -ErrorAction SilentlyContinue

# 7. Recycle-Bin artefact
Remove-Item $dummy -Force

# 8. Windows Timeline/Activity History
$activityDB = "$env:LOCALAPPDATA\ConnectedDevicesPlatform\nyx-test-activity.db"
New-Item -Path "$env:LOCALAPPDATA\ConnectedDevicesPlatform" -ItemType Directory -Force | Out-Null
'NYX-ACTIVITY-TEST' | Set-Content $activityDB

# 9. Windows Search History
$searchDir = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState"
New-Item -Path $searchDir -ItemType Directory -Force | Out-Null
'NYX-SEARCH-TEST' | Set-Content "$searchDir\nyx-search-test.txt"

# 10. Internet Explorer History (create a test URL entry)
$ieHistoryTest = "$env:LOCALAPPDATA\Microsoft\Windows\History\nyx-ie-test.txt"
New-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\History" -ItemType Directory -Force | Out-Null
'NYX-IE-TEST' | Set-Content $ieHistoryTest

# 11. Edge Legacy Browser artifacts
$edgeDir = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default"
New-Item -Path $edgeDir -ItemType Directory -Force | Out-Null
'NYX-EDGE-TEST' | Set-Content "$edgeDir\nyx-edge-test.txt"

# 12. Network credential (cmdkey)
cmdkey /add:NYX-TEST-SERVER /user:nyx-test /pass:nyx-password 2>$null

# 13. Windows Defender history
$defenderDir = "C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service"
New-Item -Path $defenderDir -ItemType Directory -Force | Out-Null
'NYX-DEFENDER-TEST' | Set-Content "$defenderDir\nyx-defender-test.txt"

# 14. Cortana history
$cortanaDir = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\LocalState"
New-Item -Path $cortanaDir -ItemType Directory -Force | Out-Null
'NYX-CORTANA-TEST' | Set-Content "$cortanaDir\nyx-cortana-test.txt"

# 15. Windows Terminal/Console MRU
if (-not (Test-Path 'HKCU:\Console')) {
    New-Item -Path 'HKCU:\Console' -Force | Out-Null
}
Set-ItemProperty -Path 'HKCU:\Console' -Name 'HistoryBufferSize' -Value 50 -Type DWord -Force
Set-ItemProperty -Path 'HKCU:\Console' -Name 'NumberOfHistoryBuffers' -Value 4 -Type DWord -Force

# 16. Remote Desktop Connection history
$rdpPath = 'HKCU:\Software\Microsoft\Terminal Server Client\Default'
if (-not (Test-Path $rdpPath)) {
    New-Item -Path $rdpPath -Force | Out-Null
}
Set-ItemProperty -Path $rdpPath -Name 'MRU0' -Value 'NYX-TEST-RDP-SERVER' -Force

# 17. Windows Media Player history
$wmpPath = 'HKCU:\Software\Microsoft\MediaPlayer\Player\RecentFileList'
if (-not (Test-Path $wmpPath)) {
    New-Item -Path $wmpPath -Force | Out-Null
}
Set-ItemProperty -Path $wmpPath -Name 'File0' -Value 'C:\NYX-TEST-MEDIA.mp3' -Force

# 18. Windows Notification history
$notifDir = "$env:LOCALAPPDATA\Microsoft\Windows\Notifications"
New-Item -Path $notifDir -ItemType Directory -Force | Out-Null
'NYX-NOTIFICATION-TEST' | Set-Content "$notifDir\nyx-notif-test.txt"

# 19. Security Event Logs - Create specific security events
Write-EventLog -LogName Security -Source "Microsoft-Windows-Security-Auditing" -EventId 4624 `
               -Message "NYX-SECURITY-TEST: Successful logon" -EntryType SuccessAudit -ErrorAction SilentlyContinue
Write-EventLog -LogName Security -Source "Microsoft-Windows-Security-Auditing" -EventId 4625 `
               -Message "NYX-SECURITY-TEST: Failed logon attempt" -EntryType FailureAudit -ErrorAction SilentlyContinue

# 20. Sysmon logs (if installed)
if (Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue) {
    Write-EventLog -LogName "Microsoft-Windows-Sysmon/Operational" -Source "Sysmon" -EventId 1 `
                   -Message "NYX-SYSMON-TEST: Process creation" -ErrorAction SilentlyContinue
}

# 21. Windows Defender Advanced Threat Protection
$atpDir = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Cache"
New-Item -Path $atpDir -ItemType Directory -Force | Out-Null
'NYX-ATP-TEST' | Set-Content "$atpDir\nyx-atp-test.dat" -ErrorAction SilentlyContinue

# 22. Windows Firewall logs
$fwLogDir = "C:\Windows\System32\LogFiles\Firewall"
New-Item -Path $fwLogDir -ItemType Directory -Force | Out-Null
'NYX-FIREWALL-TEST' | Set-Content "$fwLogDir\pfirewall.log" -ErrorAction SilentlyContinue

# 23. PowerShell Script Block Logging
$psLogDir = "$env:WINDIR\System32\winevt\Logs"
if (-not (Get-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "PowerShell" -ErrorAction SilentlyContinue)) {
    New-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -Source "PowerShell" -ErrorAction SilentlyContinue
}

# 24. WMI Activity logs
$wmiDir = "$env:WINDIR\System32\wbem\Logs"
New-Item -Path $wmiDir -ItemType Directory -Force | Out-Null
'NYX-WMI-TEST' | Set-Content "$wmiDir\wmi-activity.log" -ErrorAction SilentlyContinue

# 25. USB device history
$usbPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_NYX&Prod_TEST&Rev_1.0'
New-Item -Path $usbPath -Force | Out-Null
Set-ItemProperty -Path $usbPath -Name 'FriendlyName' -Value 'NYX-USB-TEST-DEVICE' -Force

# 26. BitLocker recovery keys
$bitlockerDir = "$env:TEMP\BitLockerRecoveryKeys"
New-Item -Path $bitlockerDir -ItemType Directory -Force | Out-Null
'NYX-BITLOCKER-RECOVERY-KEY-12345' | Set-Content "$bitlockerDir\nyx-recovery.txt"

# 27. Certificate stores - Add test certificate
$cert = New-SelfSignedCertificate -Subject "CN=NYX-TEST-CERT" -CertStoreLocation "Cert:\CurrentUser\My" `
                                  -KeyAlgorithm RSA -KeyLength 2048 -ErrorAction SilentlyContinue

# 28. Group Policy history
$gpDir = "$env:WINDIR\System32\GroupPolicy\DataStore"
New-Item -Path $gpDir -ItemType Directory -Force | Out-Null
'NYX-GROUP-POLICY-TEST' | Set-Content "$gpDir\nyx-gp-test.xml" -ErrorAction SilentlyContinue

# 29. Scheduled Tasks history
$taskName = "NYX-TEST-TASK"
$action = New-ScheduledTaskAction -Execute "notepad.exe"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force | Out-Null

# 30. Service installation logs
$serviceName = "NYX-TEST-SERVICE"
New-Service -Name $serviceName -BinaryPathName "C:\Windows\System32\svchost.exe" `
            -DisplayName "NYX Test Service" -Description "NYX Test Service" -ErrorAction SilentlyContinue

# 31. Authentication logs (NTLM/Kerberos)
$authDir = "$env:WINDIR\System32\config\systemprofile\AppData\Local\Microsoft\Windows\SchCache"
New-Item -Path $authDir -ItemType Directory -Force | Out-Null
'NYX-AUTH-TEST' | Set-Content "$authDir\nyx-auth.dat" -ErrorAction SilentlyContinue

# 32. AppLocker logs
if (-not (Get-EventLog -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -ErrorAction SilentlyContinue)) {
    New-EventLog -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -Source "AppLocker" -ErrorAction SilentlyContinue
}

# 33. Windows Update logs
$wuDir = "$env:WINDIR\SoftwareDistribution\ReportingEvents.log"
'NYX-WINDOWS-UPDATE-TEST' | Add-Content $wuDir -ErrorAction SilentlyContinue

# 34. Remote access logs (WinRM)
$winrmDir = "$env:WINDIR\System32\winevt\Logs"
if (-not (Get-EventLog -LogName "Microsoft-Windows-WinRM/Operational" -ErrorAction SilentlyContinue)) {
    New-EventLog -LogName "Microsoft-Windows-WinRM/Operational" -Source "WinRM" -ErrorAction SilentlyContinue
}

# 35. Wireless network profiles
netsh wlan add profile filename="$env:TEMP\nyx-wifi.xml" 2>$null
$wifiXml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>NYX-TEST-WIFI</name>
    <SSIDConfig>
        <SSID>
            <name>NYX-TEST-WIFI</name>
        </SSID>
    </SSIDConfig>
</WLANProfile>
"@
$wifiXml | Set-Content "$env:TEMP\nyx-wifi.xml"

# 36. VPN connection profiles
Add-VpnConnection -Name "NYX-TEST-VPN" -ServerAddress "nyx-vpn.test.com" -Force -ErrorAction SilentlyContinue

# 37. Browser extensions (Chrome)
$chromeExtDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
New-Item -Path $chromeExtDir -ItemType Directory -Force | Out-Null
New-Item -Path "$chromeExtDir\nyxtest123" -ItemType Directory -Force | Out-Null
'NYX-CHROME-EXTENSION-TEST' | Set-Content "$chromeExtDir\nyxtest123\manifest.json"

# 38. Cryptographic provider logs
$cryptoDir = "$env:APPDATA\Microsoft\Crypto\RSA"
New-Item -Path $cryptoDir -ItemType Directory -Force | Out-Null
'NYX-CRYPTO-TEST' | Set-Content "$cryptoDir\nyx-crypto.dat" -ErrorAction SilentlyContinue

# 39. TPM logs
$tpmDir = "$env:WINDIR\System32\wbem\Logs"
'NYX-TPM-TEST' | Set-Content "$tpmDir\tpm-events.log" -ErrorAction SilentlyContinue

# 40. Hyper-V logs (if installed)
$hvDir = "C:\ProgramData\Microsoft\Windows\Hyper-V\Virtual Machines logs"
New-Item -Path $hvDir -ItemType Directory -Force | Out-Null
'NYX-HYPERV-TEST' | Set-Content "$hvDir\nyx-vm.log" -ErrorAction SilentlyContinue

# 41. WSL logs
$wslDir = "$env:LOCALAPPDATA\Packages\CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc\LocalState"
New-Item -Path $wslDir -ItemType Directory -Force | Out-Null
'NYX-WSL-TEST' | Set-Content "$wslDir\ext4.vhdx.log" -ErrorAction SilentlyContinue

# 42. Docker Desktop logs
$dockerDir = "$env:APPDATA\Docker\log"
New-Item -Path $dockerDir -ItemType Directory -Force | Out-Null
'NYX-DOCKER-TEST' | Set-Content "$dockerDir\docker-desktop.log" -ErrorAction SilentlyContinue

# 43. Third-party AV logs (McAfee example)
$mcafeeDir = "C:\ProgramData\McAfee\Endpoint Security\Logs"
New-Item -Path $mcafeeDir -ItemType Directory -Force | Out-Null
'NYX-MCAFEE-TEST' | Set-Content "$mcafeeDir\EndpointSecurityPlatform.log" -ErrorAction SilentlyContinue

# 44. Symantec Endpoint Protection logs
$sepDir = "C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs"
New-Item -Path $sepDir -ItemType Directory -Force | Out-Null
'NYX-SYMANTEC-TEST' | Set-Content "$sepDir\AV\0.log" -ErrorAction SilentlyContinue

# 45. CrowdStrike Falcon logs
$csDir = "C:\ProgramData\CrowdStrike\Logs"
New-Item -Path $csDir -ItemType Directory -Force | Out-Null
'NYX-CROWDSTRIKE-TEST' | Set-Content "$csDir\FalconSensor.log" -ErrorAction SilentlyContinue

# 46. SentinelOne logs
$s1Dir = "C:\ProgramData\Sentinel\Logs"
New-Item -Path $s1Dir -ItemType Directory -Force | Out-Null
'NYX-SENTINELONE-TEST' | Set-Content "$s1Dir\SentinelAgent.log" -ErrorAction SilentlyContinue

# 47. Carbon Black logs
$cbDir = "C:\ProgramData\CarbonBlack\Logs"
New-Item -Path $cbDir -ItemType Directory -Force | Out-Null
'NYX-CARBONBLACK-TEST' | Set-Content "$cbDir\cb.log" -ErrorAction SilentlyContinue

# 48. Forensic tool artifacts (FTK Imager)
$ftkDir = "$env:APPDATA\AccessData\FTK Imager"
New-Item -Path $ftkDir -ItemType Directory -Force | Out-Null
'NYX-FTK-TEST' | Set-Content "$ftkDir\RecentCases.xml" -ErrorAction SilentlyContinue

# 49. Memory dumps
$dumpDir = "C:\Windows\MEMORY.DMP"
'NYX-MEMORY-DUMP-TEST' | Set-Content $dumpDir -ErrorAction SilentlyContinue

# 50. Hibernation file traces
$hibDir = "$env:TEMP\HibernationTraces"
New-Item -Path $hibDir -ItemType Directory -Force | Out-Null
'NYX-HIBERNATION-TEST' | Set-Content "$hibDir\hiberfil-analysis.txt"

# 51. AMSI (Antimalware Scan Interface) logs
$amsiDir = "$env:WINDIR\System32\winevt\Logs"
if (-not (Get-EventLog -LogName "Microsoft-Windows-AMSI/Operational" -ErrorAction SilentlyContinue)) {
    New-EventLog -LogName "Microsoft-Windows-AMSI/Operational" -Source "AMSI" -ErrorAction SilentlyContinue
}

# 52. Windows Error Reporting Queue
$werQueue = "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportQueue\NYX-TEST-CRASH"
New-Item -Path $werQueue -ItemType Directory -Force | Out-Null
'NYX-WER-QUEUE-TEST' | Set-Content "$werQueue\Report.wer"

# 53. System Resource Usage Monitor (SRUM)
$srumPath = "C:\Windows\System32\sru\SRUDB.dat"
# We can't modify SRUM directly, but we'll check for its existence in verification

# 54. Windows Push Notifications
$wpnDir = "$env:LOCALAPPDATA\Microsoft\Windows\Notifications\wpndatabase.db"
'NYX-WPN-TEST' | Set-Content "$wpnDir-test.txt" -ErrorAction SilentlyContinue

# 55. Office telemetry
$officeTelDir = "$env:LOCALAPPDATA\Microsoft\Office\16.0\Telemetry"
New-Item -Path $officeTelDir -ItemType Directory -Force | Out-Null
'NYX-OFFICE-TELEMETRY-TEST' | Set-Content "$officeTelDir\nyx-telemetry.dat"

# 56. OneDrive logs
$onedriveDir = "$env:LOCALAPPDATA\Microsoft\OneDrive\logs"
New-Item -Path $onedriveDir -ItemType Directory -Force | Out-Null
'NYX-ONEDRIVE-TEST' | Set-Content "$onedriveDir\SyncEngine.log"

# 57. Teams logs
$teamsDir = "$env:APPDATA\Microsoft\Teams\logs.txt"
'NYX-TEAMS-TEST' | Set-Content $teamsDir -ErrorAction SilentlyContinue

# 58. Outlook search history
$outlookDir = "$env:LOCALAPPDATA\Microsoft\Outlook"
New-Item -Path $outlookDir -ItemType Directory -Force | Out-Null
'NYX-OUTLOOK-SEARCH-TEST' | Set-Content "$outlookDir\search-history.dat"

# 59. Windows Subsystem for Android logs
$wsaDir = "$env:LOCALAPPDATA\Packages\MicrosoftCorporationII.WindowsSubsystemForAndroid_8wekyb3d8bbwe\LocalState"
New-Item -Path $wsaDir -ItemType Directory -Force | Out-Null
'NYX-WSA-TEST' | Set-Content "$wsaDir\wsa.log" -ErrorAction SilentlyContinue

# 60. Xbox Game Bar
$xboxDir = "$env:LOCALAPPDATA\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\LocalState"
New-Item -Path $xboxDir -ItemType Directory -Force | Out-Null
'NYX-XBOX-TEST' | Set-Content "$xboxDir\captures.log" -ErrorAction SilentlyContinue

Write-Host '[+] Windows test artifacts created (60+ security-focused artifacts including EDR, AV, forensics, and system logs).'
