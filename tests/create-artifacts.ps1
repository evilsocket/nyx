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

Write-Host '[+] Windows test artefacts created (including Terminal MRU, RDP, Media Player, and Notification artifacts).'
