# Nyx

Nyx (the personification and primordial goddess of the night in Greek mythology) is a self-contained script for cleaning forensic traces on Linux, macOS, and Windows.

> **⚠️ Disclaimer:**  
> Nyx is **alpha software** and is provided as-is, without any warranty.  

## Features

### Linux
- `shell` - Shell history files (.bash_history, .zsh_history, etc.)
- `logs` - System logs (/var/log/*)
- `audit` - Audit logs (auditd)
- `temp` - Temporary files, trash directories, core dumps
- `network` - Network traces (ARP cache, NetworkManager)
- `user` - User traces (thumbnails, GNOME Tracker, Zeitgeist)

### macOS
- `shell` - Shell history files
- `macos` - macOS specific traces (.DS_Store, Spotlight, system logs, appfirewall.log)
- `audit` - Audit (BSM) logs (/var/audit/*)
- `browser` - Safari history and cache
- `unified` - Unified logs (10.12+)
- `fileevents` - FSEvents and quarantine database
- `usage` - App usage traces (KnowledgeC, notifications)

### Windows
- `events` - Windows Event Logs (including Sysmon, WinRM)
- `history` - PowerShell/CMD history, prefetch, jump lists
- `registry` - Registry MRUs, USB history, BAM, ShellBags, UserAssist
- `filesystem` - USN journal, recycle bin, thumbcache
- `temp` - Temporary files, DNS cache, shadow copies, WER archives, crash dumps

## Quick Start

### Linux/macOS

```bash
# Download nyx.sh
wget https://github.com/evilsocket/nyx/raw/refs/heads/main/nyx.sh
chmod +x nyx.sh

# Run with dry-run first
sudo ./nyx.sh --dry-run

# Run all modules
sudo ./nyx.sh --force
```

### Windows

```powershell
# Download nyx.ps1 (run as Administrator)
Invoke-WebRequest -Uri "https://github.com/evilsocket/nyx/raw/refs/heads/main/nyx.ps1" -OutFile "nyx.ps1"

# Run with dry-run first
.\nyx.ps1 -DryRun

# Run all modules
.\nyx.ps1 -Force

# Enable audit logging
.\nyx.ps1 -Force -LogFile "nyx-audit.log"
```

## Usage

### Linux/macOS (nyx.sh)

```bash
# Show help
./nyx.sh --help

# List available modules
./nyx.sh --list

# Dry run with verbose output
./nyx.sh --dry-run --debug

# Clean specific modules
sudo ./nyx.sh -m shell,logs

# Force run without confirmation
sudo ./nyx.sh --force
```

### Windows (nyx.ps1)

```powershell
# Show help
.\nyx.ps1 -Help

# List available modules
.\nyx.ps1 -List

# Dry run with verbose output
.\nyx.ps1 -DryRun -Debug

# Clean specific modules (case-insensitive)
.\nyx.ps1 -Modules EVENTS,TEMP -Force

# Advanced mode with memory hardening
.\nyx.ps1 -Advanced -Force

# Enable comprehensive audit logging
.\nyx.ps1 -Force -LogFile "audit.log" -Debug
```

## Contributors

<a href="https://github.com/evilsocket/nyx/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=evilsocket/nyx" alt="nyx project contributors" />
</a>

## License

`bettercap` is made with ♥ and released under the GPL 3 license.

## Stargazers over time

[![Stargazers over time](https://starchart.cc/evilsocket/nyx.svg)](https://starchart.cc/evilsocket/nyx)
