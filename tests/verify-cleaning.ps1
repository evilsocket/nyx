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
