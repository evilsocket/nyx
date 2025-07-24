# Nyx

Nyx (the personification and primordial goddess of the night in Greek mythology) is a single, self-contained cross-platform shell script for cleaning forensic traces on Linux, macOS, and Windows systems.

> **⚠️ Disclaimer:**  
> Nyx is **alpha software** and is provided as-is, without any warranty.  
> **Use with extreme caution!** This tool will permanently delete forensic traces and may impact system stability or data integrity.  
> Always review the script and test in a safe environment before running on production or important systems.

## Features

- **Single file, no dependencies** - Just download and run.
- **Cross-platform** - Works on Linux, macOS, and Windows (with Git Bash/WSL).
- **Modular design** - Clean specific traces, or everything.
- **Safe dry-run mode** - Test what would be cleaned without making changes.
- **Verbose output** - See exactly what's being cleaned.

## Quick Start

### Download and Run

```bash
# With wget (Linux/macOS)
wget -qO- https://raw.githubusercontent.com/evilsocket/nyx/main/nyx.sh | sudo sh

# With curl (Linux/macOS)
curl -sSL https://raw.githubusercontent.com/evilsocket/nyx/main/nyx.sh | sudo sh

# Windows (Git Bash as Administrator)
curl -sSL https://raw.githubusercontent.com/evilsocket/nyx/main/nyx.sh | sh
```

## Usage

```bash
# Show help
./nyx.sh --help

# List available modules for your OS
./nyx.sh --list

# Dry run (see what would be cleaned)
./nyx.sh --dry-run

# Dry run with verbose output
./nyx.sh --dry-run --debug

# Clean specific modules
./nyx.sh -m shell,logs

# Force run without confirmation
sudo ./nyx.sh --force

# Clean only shell history
sudo ./nyx.sh -m shell

# Enable advanced options (Windows memory hardening)
sudo ./nyx.sh --advanced
```

## Available Modules

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

## Requirements

- **Linux**: Any modern distribution with standard shell
- **macOS**: macOS 10.10 or later
- **Windows**: Windows 7 or later with Git Bash, WSL, or Cygwin
- **Privileges**: Root/Administrator access required for several of the modules (except for dry-run)

## Development

The script is designed to be:

- POSIX-compliant for maximum compatibility
- Modular with clearly separated cleaning functions
- Safe with proper error handling
- Readable with consistent style

### Adding New Modules

To add a new cleaning module:

1. Create a new function: `clean_<os>_<module>()`
2. Use the standard pattern:
   - `print_info` for status
   - `truncate_file` or `safe_remove` for file operations
   - Update `CLEANED_COUNT`
   - `print_success` when done
3. Add to `run_cleaners()` function
4. Update `list_modules()` function

## Contributors

<a href="https://github.com/evilsocket/nyx/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=evilsocket/nyx" alt="nyx project contributors" />
</a>

## License

`bettercap` is made with ♥ and released under the GPL 3 license.

## Stargazers over time

[![Stargazers over time](https://starchart.cc/evilsocket/nyx.svg)](https://starchart.cc/evilsocket/nyx)
