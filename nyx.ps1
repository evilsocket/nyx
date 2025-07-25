#!/usr/bin/env pwsh
# Nyx - Cross-platform anti-forensics trace cleaner
# Developed by Simone Margaritelli <evilsocket@gmail.com>
# Released under the GPLv3 license.

param(
    [Alias("h")]
    [switch]$Help,
    [Alias("v")]
    [switch]$Version,
    [Alias("n")]
    [switch]$DryRun,
    [Alias("d")]
    [switch]$Debug,
    [Alias("l")]
    [switch]$List,
    [Alias("m")]
    [string]$Modules = "",
    [Alias("f")]
    [switch]$Force,
    [Alias("a")]
    [switch]$Advanced,
    [string]$LogFile = ""
)

# Global variables
$script:NYX_VERSION = '1.0.0-alpha'
$script:CLEANED_COUNT = 0
$script:FAILED_COUNT = 0

# Enable strict mode to catch typos during future edits
Set-StrictMode -Version Latest

# Guard the logfile writer - create file/directory if needed
if ($LogFile) { 
    New-Item -ItemType File -Path $LogFile -Force -ErrorAction SilentlyContinue | Out-Null
}

# Print functions with color compatibility
function Print-Banner {
    $sep = '=' * 48
    $msg2 = '              Nyx v' + $script:NYX_VERSION
    
    if ($Host.UI.SupportsVirtualTerminal) {
        Write-Host $sep -ForegroundColor Blue
        Write-Host $msg2 -ForegroundColor Blue
        Write-Host $sep -ForegroundColor Blue
    } else {
        Write-Host $sep
        Write-Host $msg2
        Write-Host $sep
    }
    Write-Host ""
}

function Print-Warning {
    $msg1 = 'WARNING: This tool will permanently delete forensic traces!'
    $msg2 = 'This action cannot be undone and may impact system stability.'
    
    if ($Host.UI.SupportsVirtualTerminal) {
        Write-Host $msg1 -ForegroundColor Yellow
        Write-Host $msg2 -ForegroundColor Yellow
    } else {
        Write-Host $msg1
        Write-Host $msg2
    }
    Write-Host ""
}

function Print-Error {
    param([string]$Message)
    $msg = '[ERROR] ' + $Message
    if ($Host.UI.SupportsVirtualTerminal) {
        Write-Host $msg -ForegroundColor Red
    } else {
        Write-Host $msg
    }
    
    # Optional logging to file for development/audit trail
    if ($LogFile) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] $msg"
        Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
}

function Print-Success {
    param([string]$Message)
    $msg = '[v] ' + $Message
    if ($Host.UI.SupportsVirtualTerminal) {
        Write-Host $msg -ForegroundColor Green
    } else {
        Write-Host $msg
    }
    
    # Optional logging to file for full audit trail
    if ($LogFile) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Add-Content -Path $LogFile -Value "[$timestamp] $msg" -ErrorAction SilentlyContinue
    }
}

function Print-Info {
    param([string]$Message)
    $msg = '[*] ' + $Message
    if ($Host.UI.SupportsVirtualTerminal) {
        Write-Host $msg -ForegroundColor Blue
    } else {
        Write-Host $msg
    }
    
    # Optional logging to file for full audit trail
    if ($LogFile) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Add-Content -Path $LogFile -Value "[$timestamp] $msg" -ErrorAction SilentlyContinue
    }
}

function Print-Verbose {
    param([string]$Message)
    if ($Debug) {
        $msg = '[DEBUG] ' + $Message
        Write-Host $msg
        
        # Optional logging to file for development/audit trail
        if ($LogFile) {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logEntry = "[$timestamp] $msg"
            Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
        }
    }
}

# Check if running as Administrator
function Check-Privileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Print-Error 'This script must be run as Administrator'
        exit 1
    }
}

# Safe file operations
function Safe-Remove {
    param([string]$Path)
    
    if (Test-Path $Path) {
        if ($DryRun) {
            $msg = '[DRY RUN] Would remove: ' + $Path
            Print-Verbose $msg
            return $true
        } else {
            try {
                Remove-Item -Path $Path -Force -ErrorAction Stop
                return $true
            } catch {
                $script:FAILED_COUNT++
                Print-Verbose "Failed to remove: $Path"
                return $false
            }
        }
    }
    return $false
}

function Truncate-File {
    param([string]$Path)
    
    if (Test-Path $Path) {
        if ($DryRun) {
            $msg = '[DRY RUN] Would truncate: ' + $Path
            Print-Verbose $msg
            return $true
        } else {
            try {
                Clear-Content -Path $Path -Force -ErrorAction Stop
                return $true
            } catch {
                $script:FAILED_COUNT++
                Print-Verbose "Failed to truncate: $Path"
                return $false
            }
        }
    }
    return $false
}

# Module: Windows Event Logs
function Clean-WindowsEventLogs {
    Print-Info 'Cleaning Windows event logs...'
    $count = 0
    
    if ($DryRun) {
        Print-Verbose '[DRY RUN] Would clear all event logs'
        $count = 180  # Approximate number of logs on Win11
    } else {
        try {
            # Get Administrative and Operational logs (faster than wevtutil el)
            $allLogs = Get-WinEvent -ListLog * | 
                Where-Object { $_.LogType -eq 'Administrative' -or $_.LogType -eq 'Operational' } |
                Select-Object -ExpandProperty LogName
            
            if ($allLogs) {
                foreach ($log in $allLogs) {
                    try {
                        wevtutil cl "$log" 2>$null
                        $count++
                    } catch { 
                        $script:FAILED_COUNT++
                        Print-Verbose "Failed to clear event log: $log"
                    }
                }
            }
            
            # Backup method for critical logs
            $criticalLogs = @('Application', 'System', 'Security')
            foreach ($log in $criticalLogs) {
                try {
                    Clear-EventLog -LogName $log -ErrorAction SilentlyContinue
                } catch { 
                    $script:FAILED_COUNT++
                    Print-Verbose "Failed to clear critical event log: $log"
                }
            }
            
            Print-Verbose "Cleared $count event logs"
        } catch {
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to enumerate event logs'
        }
    }
    
    $script:CLEANED_COUNT += $count
    $msg = 'Event logs cleaned (' + $count + ' logs)'
    Print-Success $msg
}

# Module: Windows History
function Clean-WindowsHistory {
    Print-Info 'Cleaning Windows history...'
    $count = 0
    
    # PowerShell history
    $psHistory = $env:APPDATA + '\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Truncate-File $psHistory) {
        $count++
        Print-Verbose 'Cleaned PowerShell history'
    }
    
    # Clear command prompt history
    if (-not $DryRun) {
        try {
            & doskey /reinstall 2>$null
            $count++
        } catch { 
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clear command prompt history'
        }
    }
    
    # Clear Run dialog history
    if ($DryRun) {
        Print-Verbose '[DRY RUN] Would clear Run dialog history'
        $count++
    } else {
        try {
            reg delete 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' /va /f 2>$null
            $count++
        } catch { 
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clear Run dialog history'
        }
    }
    
    # Clear prefetch and Superfetch/ReadyBoot
    if (-not $DryRun) {
        $originalAcl = $null
        # In Advanced mode, grant access to Prefetch folder if needed
        if ($Advanced) {
            try {
                # Store original ACL before modification
                $originalAcl = icacls "$env:SystemRoot\Prefetch" /save - 2>$null
                icacls "$env:SystemRoot\Prefetch" /grant "$env:USERNAME:(OI)(CI)F" /T 2>$null
                Print-Verbose 'Granted Prefetch folder access for advanced cleaning'
            } catch {
                $script:FAILED_COUNT++
                Print-Verbose 'Failed to grant Prefetch folder access'
            }
        }
        
        Remove-Item -Path 'C:\Windows\Prefetch\*.pf' -Force -ErrorAction SilentlyContinue
        Remove-Item -Path 'C:\Windows\Prefetch\ReadyBoot\*.etl' -Force -ErrorAction SilentlyContinue
        $count++
        
        # Restore original ACL if we modified it
        if ($Advanced -and $originalAcl) {
            try {
                $originalAcl | icacls "$env:SystemRoot\Prefetch" /restore /T 2>$null
                Print-Verbose 'Restored original Prefetch folder ACL'
            } catch {
                Print-Verbose 'Failed to restore original Prefetch folder ACL'
            }
        }
    }
    
    # Clear LNK files
    if (-not $DryRun) {
        $lnkPath = $env:APPDATA + '\Microsoft\Windows\Recent\*.lnk'
        Remove-Item -Path $lnkPath -Force -ErrorAction SilentlyContinue
        $count++
    }
    
    # Clear Jump Lists
    if (-not $DryRun) {
        $autoPath = $env:APPDATA + '\Microsoft\Windows\Recent\AutomaticDestinations\*'
        $customPath = $env:APPDATA + '\Microsoft\Windows\Recent\CustomDestinations\*'
        Remove-Item -Path $autoPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $customPath -Force -ErrorAction SilentlyContinue
        $count++
    }
    
    # Windows Timeline/Activity History
    if (-not $DryRun) {
        $activityPath = $env:LOCALAPPDATA + '\ConnectedDevicesPlatform\*'
        Remove-Item -Path $activityPath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Windows Timeline/Activity History'
    }
    
    # Windows Search History
    if (-not $DryRun) {
        $searchPath = $env:LOCALAPPDATA + '\Packages\Microsoft.Windows.Search_*\LocalState\*'
        Remove-Item -Path $searchPath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Windows Search History'
    }
    
    # Internet Explorer History
    if (-not $DryRun) {
        RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 1 2>$null
        # Also clean the History folder
        $historyPath = $env:LOCALAPPDATA + '\Microsoft\Windows\History\*'
        Remove-Item -Path $historyPath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Internet Explorer History'
    }
    
    # Edge Browser History (Legacy)
    if (-not $DryRun) {
        $edgePath = $env:LOCALAPPDATA + '\Packages\Microsoft.MicrosoftEdge_*\AC\*'
        Remove-Item -Path $edgePath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Legacy Edge History'
    }
    
    # Chromium-Edge browsing history
    $edgeChromDb = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    if (-not $DryRun -and (Test-Path $edgeChromDb)) { 
        Remove-Item $edgeChromDb -Force -ErrorAction SilentlyContinue; 
        $count++; 
        Print-Verbose 'Cleaned Edge (Chromium) History' 
    }
    
    $script:CLEANED_COUNT += $count
    $msg = 'Windows history cleaned (' + $count + ' items)'
    Print-Success $msg
}

# Module: Windows Registry MRUs
function Clean-WindowsRegistry {
    Print-Info 'Cleaning Windows registry MRUs...'
    $count = 0
    
    # List of MRU registry keys to clean
    $mruKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
        'HKCU:\Software\Microsoft\Windows\Shell\Bags',
        'HKCU:\Software\Microsoft\Windows\Shell\BagMRU',
        'HKCU:\Software\Microsoft\Windows\ShellNoRoam\Bags',
        'HKCU:\Software\Microsoft\Windows\ShellNoRoam\BagMRU',
        'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags',
        'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    )
    
    # Handle Office MRUs more efficiently (compatible with PS5)
    try {
        $officeKeys = Get-ChildItem 'HKCU:\Software\Microsoft\Office' -Recurse -ErrorAction SilentlyContinue |
                      Where-Object { $_.Property -match 'File MRU|Place MRU' }
        $mruKeys += $officeKeys | ForEach-Object { $_.PSPath }
    } catch {
        $script:FAILED_COUNT++
        Print-Verbose 'Failed to enumerate Office MRUs'
    }
    
    foreach ($key in $mruKeys) {
        if ($DryRun) {
            $msg = '[DRY RUN] Would clear registry key: ' + $key
            Print-Verbose $msg
            $count++
        } else {
            try {
                if (Test-Path $key) {
                    Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
                    $count++
                }
            } catch { 
                $script:FAILED_COUNT++
                Print-Verbose "Failed to remove registry key: $key"
            }
        }
    }
    
    # USB history
    if (-not $DryRun) {
        try {
            reg delete 'HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR' /f 2>$null
            $count++
        } catch { 
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clear USB history'
        }
    }
    
    # Mounted devices
    if (-not $DryRun) {
        try {
            reg delete 'HKLM\SYSTEM\MountedDevices' /va /f 2>$null
            $count++
        } catch { 
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clear mounted devices'
        }
    }
    
    # BAM (Background Activity Monitor)
    if (-not $DryRun) {
        try {
            reg delete 'HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' /f 2>$null
            $count++
        } catch { 
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clear BAM history'
        }
    }
    
    # ShimCache/AppCompat
    if (-not $DryRun) {
        try {
            reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' /va /f 2>$null
            $count++
        } catch { 
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clear ShimCache/AppCompat'
        }
    }
    
    # Windows Terminal MRU
    if (-not $DryRun) {
        try {
            reg delete 'HKCU\Console' /v HistoryBufferSize /f 2>$null
            reg delete 'HKCU\Console' /v NumberOfHistoryBuffers /f 2>$null
            $count++
        } catch { 
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clear Windows Terminal MRU'
        }
    }
    
    # Remote Desktop Connection history
    if (-not $DryRun) {
        try {
            reg delete 'HKCU\Software\Microsoft\Terminal Server Client\Default' /va /f 2>$null
            reg delete 'HKCU\Software\Microsoft\Terminal Server Client\Servers' /f 2>$null
            $count++
        } catch { 
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clear RDP connection history'
        }
    }
    
    # Windows Media Player history
    if (-not $DryRun) {
        try {
            reg delete 'HKCU\Software\Microsoft\MediaPlayer\Player\RecentFileList' /va /f 2>$null
            reg delete 'HKCU\Software\Microsoft\MediaPlayer\Player\RecentURLList' /va /f 2>$null
            $count++
        } catch { 
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clear Windows Media Player history'
        }
    }
    
    $script:CLEANED_COUNT += $count
    $msg = 'Registry MRUs cleaned (' + $count + ' keys)'
    Print-Success $msg
}

# Module: Windows File System Traces
function Clean-WindowsFilesystemTraces {
    Print-Info 'Cleaning Windows file system traces...'
    $count = 0
    
    # Get list of drives dynamically (using CIM instead of deprecated WMI)
    $drives = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3").DeviceID
    
    # Clean USN Journal
    if (-not $DryRun) {
        foreach ($drive in $drives) {
            try {
                fsutil usn deletejournal /D $drive 2>$null
            } catch { 
                $script:FAILED_COUNT++
                Print-Verbose "Failed to delete USN journal for drive: $drive"
            }
        }
        $count++
    }
    
    # Empty Recycle Bin
    if (-not $DryRun) {
        foreach ($drive in $drives) {
            $recycleBin = $drive + '\$Recycle.Bin'
            if (Test-Path $recycleBin -ErrorAction SilentlyContinue) {
                Remove-Item -Path $recycleBin -Recurse -Force -ErrorAction SilentlyContinue 2>$null
            }
        }
        $count++
    }
    
    # Clean thumbcache
    if (-not $DryRun) {
        $thumbPath = $env:USERPROFILE + '\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db'
        Remove-Item -Path $thumbPath -Force -ErrorAction SilentlyContinue
        $count++
    }
    
    # Clean SRUDB
    if (-not $DryRun) {
        $srudb = 'C:\Windows\System32\sru\SRUDB.dat'
        if (Test-Path $srudb) {
            Remove-Item -Path $srudb -Force -ErrorAction SilentlyContinue
            $count++
        }
    }
    
    # Windows.edb (Search Index) - Only in Advanced mode
    if ($Advanced -and -not $DryRun) {
        try {
            # Stop Windows Search service temporarily
            Stop-Service -Name WSearch -Force -ErrorAction SilentlyContinue
            $searchDb = 'C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb'
            if (Test-Path $searchDb) {
                Remove-Item -Path $searchDb -Force -ErrorAction SilentlyContinue
                $count++
                Print-Verbose 'Cleaned Windows Search Index (Advanced mode)'
            }
            # Wait before restarting to avoid delayed start issues
            Start-Sleep 3
            # Restart Windows Search
            Start-Service -Name WSearch -ErrorAction SilentlyContinue
        } catch {
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clean Windows Search Index'
        }
    } elseif (-not $DryRun) {
        Print-Verbose 'Skipped Windows Search Index (use -Advanced to enable)'
    }
    
    # Notification database
    if (-not $DryRun) {
        $notifPath = $env:LOCALAPPDATA + '\Microsoft\Windows\Notifications\*'
        Remove-Item -Path $notifPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Windows Notification History'
    }
    
    # Windows Store cache - Skip this as WSReset can hang
    if (-not $DryRun) {
        Print-Verbose 'Skipped Windows Store Cache reset (can hang indefinitely)'
    }
    
    # Thumbs.db (legacy thumbnails)
    if (-not $DryRun) {
        Get-ChildItem -Path $env:USERPROFILE -Include Thumbs.db -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Removed legacy Thumbs.db files'
    }
    
    $script:CLEANED_COUNT += $count
    $msg = 'File system traces cleaned (' + $count + ' items)'
    Print-Success $msg
}

# Module: Windows Temporary Files
function Clean-WindowsTempFiles {
    Print-Info 'Cleaning Windows temporary files...'
    $count = 0
    
    # Remove temps
    if (-not $DryRun) {
        $tempPath = $env:TEMP + '\*'
        Remove-Item -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path 'C:\Windows\Temp\*' -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path 'C:\Windows\Prefetch\*.tmp' -Force -ErrorAction SilentlyContinue
        $count++
    }
    
    # Clear DNS cache
    if (-not $DryRun) {
        try {
            ipconfig /flushdns 2>$null
            if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) {
                Clear-DnsClientCache -ErrorAction SilentlyContinue
            }
            $count++
        } catch {
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clear DNS cache'
        }
    }
    
    # Clear Volume Shadow Copies (with warning)
    if (-not $DryRun) {
        Print-Verbose 'WARNING: Removing Volume Shadow Copies will delete restore points'
        try {
            vssadmin delete shadows /all /quiet 2>$null
            $count++
        } catch { 
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to delete Volume Shadow Copies'
        }
    }
    
    # Windows Error Reporting archives
    if (-not $DryRun) {
        $werPaths = @(
            'C:\ProgramData\Microsoft\Windows\WER\ReportArchive\*',
            'C:\ProgramData\Microsoft\Windows\WER\ReportQueue\*'
        )
        $werPaths += $env:LOCALAPPDATA + '\Microsoft\Windows\WER\ReportArchive\*'
        $werPaths += $env:LOCALAPPDATA + '\Microsoft\Windows\WER\ReportQueue\*'
        
        foreach ($path in $werPaths) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
        $count++
        Print-Verbose 'Cleaned Windows Error Reporting archives'
    }
    
    # Crash dumps
    if (-not $DryRun) {
        Remove-Item -Path 'C:\Windows\Minidump\*' -Force -ErrorAction SilentlyContinue
        Remove-Item -Path 'C:\Windows\MEMORY.DMP' -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned crash dumps'
    }
    
    # Memory residue hardening (optional - requires reboot to take effect)
    if ($Advanced -and -not $DryRun) {
        # Disable hibernation (removes hiberfil.sys)
        try {
            powercfg -h off 2>$null
        } catch { 
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to disable hibernation'
        }
        
        # Enable pagefile clearing at shutdown
        try {
            reg add 'HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management' /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f 2>$null
        } catch { 
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to enable pagefile clearing'
        }
        
        $count++
        Print-Verbose 'Enabled memory residue hardening (requires reboot)'
    }
    
    # Network cache and history
    if (-not $DryRun) {
        # Clear NetBIOS cache
        nbtstat -R 2>$null
        # Clear ARP cache
        arp -d * 2>$null
        # Clear network credentials
        cmdkey /list | Select-String "Target:" | ForEach-Object {
            $target = $_ -replace ".*Target: ", "" -replace " .*", ""
            cmdkey /delete:$target 2>$null
        }
        $count++
        Print-Verbose 'Cleaned network caches'
    }
    
    # Windows Defender history
    if (-not $DryRun) {
        $defenderPath = 'C:\ProgramData\Microsoft\Windows Defender\Scans\History\*'
        Remove-Item -Path $defenderPath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Windows Defender history'
    }
    
    # Cortana history
    if (-not $DryRun) {
        $cortanaPath = $env:LOCALAPPDATA + '\Packages\Microsoft.Windows.Cortana_*\LocalState\*'
        Remove-Item -Path $cortanaPath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Cortana history'
    }
    
    # Windows Defender ATP cache
    if (-not $DryRun) {
        $atpPath = 'C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Cache\*'
        Remove-Item -Path $atpPath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Windows Defender ATP cache'
    }
    
    # Windows Firewall logs
    if (-not $DryRun) {
        $fwLogPath = 'C:\Windows\System32\LogFiles\Firewall\*.log'
        Remove-Item -Path $fwLogPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Windows Firewall logs'
    }
    
    # WMI Activity logs
    if (-not $DryRun) {
        $wmiLogPath = "$env:WINDIR\System32\wbem\Logs\*.log"
        Remove-Item -Path $wmiLogPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned WMI activity logs'
    }
    
    # BitLocker recovery keys in temp
    if (-not $DryRun) {
        $bitlockerPath = "$env:TEMP\BitLockerRecoveryKeys\*"
        Remove-Item -Path $bitlockerPath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned BitLocker recovery keys from temp'
    }
    
    # Group Policy cache
    if (-not $DryRun) {
        $gpPath = "$env:WINDIR\System32\GroupPolicy\DataStore\*"
        Remove-Item -Path $gpPath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Group Policy cache'
    }
    
    # Authentication cache
    if (-not $DryRun) {
        $authPath = "$env:WINDIR\System32\config\systemprofile\AppData\Local\Microsoft\Windows\SchCache\*"
        Remove-Item -Path $authPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned authentication cache'
    }
    
    # Hibernation traces
    if (-not $DryRun) {
        $hibPath = "$env:TEMP\HibernationTraces\*"
        Remove-Item -Path $hibPath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned hibernation traces'
    }
    
    # Office telemetry
    if (-not $DryRun) {
        $officeTelPath = "$env:LOCALAPPDATA\Microsoft\Office\*\Telemetry\*"
        Remove-Item -Path $officeTelPath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Office telemetry'
    }
    
    # OneDrive logs
    if (-not $DryRun) {
        $onedrivePath = "$env:LOCALAPPDATA\Microsoft\OneDrive\logs\*"
        Remove-Item -Path $onedrivePath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned OneDrive logs'
    }
    
    # Teams logs
    if (-not $DryRun) {
        $teamsPath = "$env:APPDATA\Microsoft\Teams\logs.txt"
        if (Test-Path $teamsPath) {
            Clear-Content -Path $teamsPath -Force -ErrorAction SilentlyContinue
        }
        $count++
        Print-Verbose 'Cleaned Teams logs'
    }
    
    # Outlook search history
    if (-not $DryRun) {
        $outlookPath = "$env:LOCALAPPDATA\Microsoft\Outlook\*.dat"
        Remove-Item -Path $outlookPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Outlook search history'
    }
    
    # WSA logs
    if (-not $DryRun) {
        $wsaPath = "$env:LOCALAPPDATA\Packages\MicrosoftCorporationII.WindowsSubsystemForAndroid_*\LocalState\*.log"
        Remove-Item -Path $wsaPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Windows Subsystem for Android logs'
    }
    
    # Xbox Game Bar
    if (-not $DryRun) {
        $xboxPath = "$env:LOCALAPPDATA\Packages\Microsoft.XboxGamingOverlay_*\LocalState\*.log"
        Remove-Item -Path $xboxPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Xbox Game Bar logs'
    }
    
    $script:CLEANED_COUNT += $count
    $msg = 'Temporary files cleaned (' + $count + ' items)'
    Print-Success $msg
}

# Module: Security Products and EDR
function Clean-SecurityProducts {
    Print-Info 'Cleaning security product artifacts...'
    $count = 0
    
    # McAfee logs
    if (-not $DryRun) {
        $mcafeePath = 'C:\ProgramData\McAfee\Endpoint Security\Logs\*'
        Remove-Item -Path $mcafeePath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned McAfee logs'
    }
    
    # Symantec Endpoint Protection logs
    if (-not $DryRun) {
        $sepPath = 'C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\*'
        Remove-Item -Path $sepPath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Symantec Endpoint Protection logs'
    }
    
    # CrowdStrike Falcon logs
    if (-not $DryRun) {
        $csPath = 'C:\ProgramData\CrowdStrike\Logs\*'
        Remove-Item -Path $csPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned CrowdStrike Falcon logs'
    }
    
    # SentinelOne logs
    if (-not $DryRun) {
        $s1Path = 'C:\ProgramData\Sentinel\Logs\*'
        Remove-Item -Path $s1Path -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned SentinelOne logs'
    }
    
    # Carbon Black logs
    if (-not $DryRun) {
        $cbPath = 'C:\ProgramData\CarbonBlack\Logs\*'
        Remove-Item -Path $cbPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Carbon Black logs'
    }
    
    # FTK Imager artifacts
    if (-not $DryRun) {
        $ftkPath = "$env:APPDATA\AccessData\FTK Imager\*"
        Remove-Item -Path $ftkPath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned FTK Imager artifacts'
    }
    
    # Hyper-V logs
    if (-not $DryRun) {
        $hvPath = 'C:\ProgramData\Microsoft\Windows\Hyper-V\Virtual Machines logs\*'
        Remove-Item -Path $hvPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Hyper-V logs'
    }
    
    # WSL logs
    if (-not $DryRun) {
        $wslPath = "$env:LOCALAPPDATA\Packages\CanonicalGroupLimited.Ubuntu_*\LocalState\*.log"
        Remove-Item -Path $wslPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned WSL logs'
    }
    
    # Docker Desktop logs
    if (-not $DryRun) {
        $dockerPath = "$env:APPDATA\Docker\log\*"
        Remove-Item -Path $dockerPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Docker Desktop logs'
    }
    
    $script:CLEANED_COUNT += $count
    $msg = 'Security product artifacts cleaned (' + $count + ' items)'
    Print-Success $msg
}

# Module: Advanced Security Traces
function Clean-AdvancedSecurity {
    Print-Info 'Cleaning advanced security traces...'
    $count = 0
    
    # Remove test certificates
    if (-not $DryRun) {
        try {
            $certs = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like "*NYX-TEST*" }
            foreach ($cert in $certs) {
                Remove-Item -Path $cert.PSPath -Force -ErrorAction SilentlyContinue
                $count++
            }
        } catch {
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clean test certificates'
        }
    }
    
    # Remove scheduled tasks
    if (-not $DryRun) {
        try {
            $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*NYX-TEST*" }
            foreach ($task in $tasks) {
                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
                $count++
            }
        } catch {
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clean scheduled tasks'
        }
    }
    
    # Remove test services
    if (-not $DryRun) {
        try {
            $services = Get-Service | Where-Object { $_.Name -like "*NYX-TEST*" }
            foreach ($service in $services) {
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                & sc.exe delete $service.Name 2>$null
                $count++
            }
        } catch {
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clean test services'
        }
    }
    
    # Remove wireless profiles
    if (-not $DryRun) {
        try {
            $profiles = netsh wlan show profiles 2>$null | Select-String "NYX-TEST"
            foreach ($profile in $profiles) {
                $profileName = ($profile -split ':')[1].Trim()
                netsh wlan delete profile name="$profileName" 2>$null
                $count++
            }
        } catch {
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clean wireless profiles'
        }
    }
    
    # Remove VPN connections
    if (-not $DryRun) {
        try {
            $vpns = Get-VpnConnection -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*NYX-TEST*" }
            foreach ($vpn in $vpns) {
                Remove-VpnConnection -Name $vpn.Name -Force -ErrorAction SilentlyContinue
                $count++
            }
        } catch {
            $script:FAILED_COUNT++
            Print-Verbose 'Failed to clean VPN connections'
        }
    }
    
    # Chrome extensions
    if (-not $DryRun) {
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\nyxtest*"
        Remove-Item -Path $chromePath -Recurse -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Chrome extensions'
    }
    
    # Cryptographic provider data
    if (-not $DryRun) {
        $cryptoPath = "$env:APPDATA\Microsoft\Crypto\RSA\*nyx*"
        Remove-Item -Path $cryptoPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned cryptographic provider data'
    }
    
    # Windows Update logs cleanup
    if (-not $DryRun) {
        $wuLogPath = "$env:WINDIR\SoftwareDistribution\ReportingEvents.log"
        if (Test-Path $wuLogPath) {
            # Remove lines containing NYX-WINDOWS-UPDATE-TEST
            $content = Get-Content $wuLogPath -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch "NYX-WINDOWS-UPDATE-TEST" }
            $content | Set-Content $wuLogPath -Force -ErrorAction SilentlyContinue
            $count++
        }
    }
    
    # Windows Push Notifications
    if (-not $DryRun) {
        $wpnPath = "$env:LOCALAPPDATA\Microsoft\Windows\Notifications\*nyx*"
        Remove-Item -Path $wpnPath -Force -ErrorAction SilentlyContinue
        $count++
        Print-Verbose 'Cleaned Windows Push Notifications'
    }
    
    $script:CLEANED_COUNT += $count
    $msg = 'Advanced security traces cleaned (' + $count + ' items)'
    Print-Success $msg
}

# Run cleaning modules
function Invoke-Cleaners {
    # Robust array creation to handle all edge cases in strict mode
    $moduleList = @()
    if ($Modules -and $Modules.Trim()) {
        $moduleList = @(($Modules -split ',') | ForEach-Object { $_.ToLower().Trim() } | Where-Object { $_ })
    }
    
    # Early exit on unknown module names
    if ($moduleList.Count -gt 0) {
        $valid = @('events','history','registry','filesystem','temp','security','advanced')
        $bad = $moduleList | Where-Object { $_ -notin $valid }
        if ($bad) { 
            Print-Error "Unknown module(s): $($bad -join ',')"
            exit 1 
        }
    }
    
    # Determine which modules to run
    $modulesToRun = @()
    if ($moduleList.Count -eq 0) {
        $modulesToRun = @('events','history','registry','filesystem','temp','security','advanced')
    } else {
        $modulesToRun = $moduleList
    }
    
    # Run modules with progress indicators
    $moduleCount = $modulesToRun.Length
    $currentModule = 0
    
    foreach ($module in $modulesToRun) {
        $currentModule++
        $percentComplete = [math]::Round(($currentModule / $moduleCount) * 100, 0)
        
        Write-Progress -Activity 'Nyx' -Status "Cleaning $module..." -PercentComplete $percentComplete
        
        switch ($module) {
            'events' { Clean-WindowsEventLogs }
            'history' { Clean-WindowsHistory }
            'registry' { Clean-WindowsRegistry }
            'filesystem' { Clean-WindowsFilesystemTraces }
            'temp' { Clean-WindowsTempFiles }
            'security' { Clean-SecurityProducts }
            'advanced' { Clean-AdvancedSecurity }
        }
    }
    
    # Complete the progress bar
    Write-Progress -Activity 'Nyx' -Completed
}

# List available modules
function Show-Modules {
    Write-Host 'Available cleaning modules:'
    Write-Host ""
    Write-Host '  events     - Windows Event Logs (including Sysmon, WinRM, Security)'
    Write-Host '  history    - PowerShell/CMD history, prefetch, jump lists'
    Write-Host '  registry   - Registry MRUs, USB history, BAM, ShimCache'
    Write-Host '  filesystem - USN journal, recycle bin, thumbcache, SRUM'
    Write-Host '  temp       - Temporary files, DNS cache, shadow copies, WER'
    Write-Host '  security   - EDR/AV logs (CrowdStrike, SentinelOne, etc.)'
    Write-Host '  advanced   - Certificates, tasks, services, VPN/WiFi profiles'
    Write-Host ""
}

# Show usage
function Show-Usage {
    Write-Host 'Usage: .\nyx.ps1 [OPTIONS]'
    Write-Host ""
    Write-Host 'Options:'
    Write-Host '  -Help, -h         Show this help message'
    Write-Host '  -Version, -v      Show version'
    Write-Host '  -DryRun, -n       Perform a dry run (no changes)'
    Write-Host '  -Debug, -d        Enable verbose output'
    Write-Host '  -List, -l         List available modules'
    Write-Host '  -Modules, -m      Comma-separated list of modules to run'
    Write-Host '  -Force, -f        Skip confirmation prompt'
    Write-Host '  -Advanced, -a     Also wipe hiberfil.sys and zero pagefile on shutdown'
    Write-Host '  -LogFile         Write all INFO / DEBUG / ERROR lines to the file'
    Write-Host ""
    Write-Host 'Examples:'
    Write-Host '  .\nyx.ps1                       # Run all modules (interactive)'
    Write-Host '  .\nyx.ps1 -DryRun               # Dry run to see what would be cleaned'
    Write-Host '  .\nyx.ps1 -Modules events,temp  # Clean only event logs and temp files'
    Write-Host '  .\nyx.ps1 -Force                # Force run without confirmation'
    Write-Host '  .\nyx.ps1 -LogFile audit.log    # Enable audit logging'
    Write-Host ""
}

# Confirmation prompt
function Confirm-Action {
    if ($Force) {
        return $true
    }
    
    if ($DryRun) {
        return $true
    }
    
    $response = Read-Host 'Do you want to continue? [y/N]'
    return ($response -match '^[yY]')
}

# Summary report
function Show-Summary {
    Write-Host ""
    Write-Host '================================================' -ForegroundColor Green
    Write-Host '              Cleaning Complete!' -ForegroundColor Green
    Write-Host '================================================' -ForegroundColor Green
    Write-Host ""
    Write-Host 'Summary:'
    $cleanedMsg = '  Total items cleaned: ' + $script:CLEANED_COUNT
    Write-Host $cleanedMsg
    $failedMsg = '  Failed operations: ' + $script:FAILED_COUNT
    Write-Host $failedMsg
    
    if ($DryRun) {
        Write-Host ""
        Write-Host 'This was a dry run. No actual changes were made.' -ForegroundColor Yellow
    }
    Write-Host ""
}

# Main function
function Main {
    # Handle command line arguments
    if ($Help) {
        Show-Usage
        exit 0
    }
    
    if ($Version) {
        $versionMsg = 'Nyx v' + $script:NYX_VERSION
        Write-Host $versionMsg
        exit 0
    }
    
    if ($List) {
        Show-Modules
        exit 0
    }
    
    # Show banner
    Print-Banner
    
    # Show warning
    Print-Warning
    
    # Check privileges (unless listing modules or dry run)
    if (-not $DryRun) {
        Check-Privileges
    }
    
    # Confirm action
    if (-not (Confirm-Action)) {
        Write-Host 'Aborted.'
        exit 0
    }
    
    # Show mode
    if ($DryRun) {
        Print-Info 'Running in DRY RUN mode - no changes will be made'
    }
    
    Print-Info 'Operating System: Windows'
    if ($Modules) {
        $msg = 'Modules: ' + $Modules
        Print-Info $msg
    } else {
        Print-Info 'Modules: all'
    }
    Write-Host ""
    
    # Run cleaners
    Invoke-Cleaners
    
    # Show summary
    Show-Summary
}

# Run main function
Main
