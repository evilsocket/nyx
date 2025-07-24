#!/bin/sh
# Nyx - Cross-platform anti-forensics trace cleaner
# Developed by Simone Margaritelli <evilsocket@gmail.com>
# Released under the GPLv3 license.
set -e

# Global variables
VERSION="1.0.0-alpha"
DRY_RUN=0
VERBOSE=0
MODULES=""
OS_TYPE=""
RESULTS=""
CLEANED_COUNT=0
FAILED_COUNT=0
ADVANCED=0

# Color codes (disabled if not TTY)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Print functions
print_banner() {
    echo "${BLUE}================================================${NC}"
    echo "${BLUE}              Nyx v${VERSION}${NC}"
    echo "${BLUE}      Anti-Forensics Trace Cleaner${NC}"
    echo "${BLUE}================================================${NC}"
    echo ""
}

print_warning() {
    echo "${YELLOW}⚠️  WARNING: This tool will permanently delete forensic traces!${NC}"
    echo "${YELLOW}This action cannot be undone and may impact system stability.${NC}"
    echo ""
}

print_error() {
    echo "${RED}[ERROR] $1${NC}" >&2
}

print_success() {
    echo "${GREEN}[✓] $1${NC}"
}

print_info() {
    echo "${BLUE}[*] $1${NC}"
}

print_verbose() {
    if [ "$VERBOSE" -eq 1 ]; then
        echo "[DEBUG] $1"
    fi
}

# OS Detection
detect_os() {
    if [ -n "$OS_TYPE" ]; then
        return
    fi
    
    case "$(uname -s)" in
        Linux*)     OS_TYPE="linux";;
        Darwin*)    OS_TYPE="macos";;
        CYGWIN*|MINGW*|MSYS*)    OS_TYPE="windows";;
        *)          
            print_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac
    
    print_verbose "Detected OS: $OS_TYPE"
}

# Check if running as root/admin
check_privileges() {
    case "$OS_TYPE" in
        linux|macos)
            if [ "$(id -u)" -ne 0 ]; then
                print_error "This script must be run as root"
                echo "Try: sudo $0 $*"
                exit 1
            fi
            ;;
        windows)
            # Check if running as Administrator
            net session >/dev/null 2>&1
            if [ $? -ne 0 ]; then
                print_error "This script must be run as Administrator"
                exit 1
            fi
            ;;
    esac
}

# Safe file operations
safe_remove() {
    local file="$1"
    if [ -f "$file" ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            print_verbose "[DRY RUN] Would remove: $file"
            return 0
        else
            rm -f "$file" 2>/dev/null && return 0 || return 1
        fi
    fi
    return 1
}

truncate_file() {
    local file="$1"
    if [ -f "$file" ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            print_verbose "[DRY RUN] Would truncate: $file"
            return 0
        else
            > "$file" 2>/dev/null && return 0 || return 1
        fi
    fi
    return 1
}

# Module: Linux Shell History
clean_linux_shell_history() {
    print_info "Cleaning Linux shell history..."
    local count=0
    
    # Get all user home directories
    local homes
    if [ "$(id -u)" -eq 0 ]; then
        homes=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $6}' /etc/passwd)
        homes="$homes /root"
    else
        homes="$HOME"
    fi
    
    for home in $homes; do
        if [ -d "$home" ]; then
            # Clean various history files
            for hist in .bash_history .zsh_history .sh_history .ash_history \
                       .fish_history .python_history .mysql_history .psql_history \
                       .sqlite_history .rediscli_history .lesshst .viminfo \
                       .wget-hsts .node_repl_history .Rhistory .gdb_history \
                       .mongo_history .docker_history; do
                if truncate_file "$home/$hist"; then
                    count=$((count + 1))
                    print_verbose "Cleaned: $home/$hist"
                fi
            done
            
            # Clean .local/share histories
            if [ -d "$home/.local/share" ]; then
                for hist in "$home/.local/share/fish/fish_history" \
                           "$home/.local/share/recently-used.xbel" \
                           "$home/.local/share/mc/history" \
                           "$home/.local/share/nano/search_history"; do
                    if truncate_file "$hist"; then
                        count=$((count + 1))
                        print_verbose "Cleaned: $hist"
                    fi
                done
            fi
        fi
    done
    
    # Clear current session history
    if [ "$DRY_RUN" -eq 0 ]; then
        history -c 2>/dev/null || true
        unset HISTFILE 2>/dev/null || true
    fi
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Shell history cleaned ($count files)"
}

# Module: Linux System Logs
clean_linux_system_logs() {
    print_info "Cleaning Linux system logs..."
    local count=0
    
    # Text-based logs
    for log in /var/log/syslog* /var/log/messages* /var/log/auth.log* \
               /var/log/secure* /var/log/kern.log* /var/log/dmesg* \
               /var/log/boot.log* /var/log/lastlog /var/log/wtmp \
               /var/log/btmp /var/log/faillog /var/log/dpkg.log* \
               /var/log/apt/history.log* /var/log/apt/term.log* \
               /var/log/alternatives.log* /var/log/yum.log* /var/log/dnf.log* \
               /var/log/cron* /var/log/mail* /var/log/maillog* \
               /var/log/exim4/* /var/log/ufw.log* /var/log/firewalld* \
               /var/log/iptables.log* /var/log/Xorg.*.log* /var/log/cups/* \
               /var/log/daemon.log* /var/log/mount.log*; do
        if truncate_file "$log"; then
            count=$((count + 1))
            print_verbose "Cleaned: $log"
        fi
    done
    
    # Journald logs
    if command -v journalctl >/dev/null 2>&1; then
        if [ "$DRY_RUN" -eq 1 ]; then
            print_verbose "[DRY RUN] Would clear journald logs"
        else
            journalctl --vacuum-size=1K >/dev/null 2>&1 || true
            journalctl --vacuum-time=1s >/dev/null 2>&1 || true
            count=$((count + 1))
        fi
    fi
    
    # Apache/Nginx logs
    for log in /var/log/apache2/*.log /var/log/nginx/*.log \
               /var/log/httpd/*.log; do
        if truncate_file "$log"; then
            count=$((count + 1))
            print_verbose "Cleaned: $log"
        fi
    done
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "System logs cleaned ($count items)"
}

# Module: Linux Audit Logs
clean_linux_audit_logs() {
    print_info "Cleaning Linux audit logs..."
    local count=0
    
    # Check if auditd is installed
    if [ -d "/var/log/audit" ]; then
        # Stop auditd temporarily
        if [ "$DRY_RUN" -eq 0 ]; then
            service auditd stop 2>/dev/null || systemctl stop auditd 2>/dev/null || true
        fi
        
        # Clean audit logs
        for log in /var/log/audit/audit.log* /var/log/audit/ausearch.log*; do
            if truncate_file "$log"; then
                count=$((count + 1))
                print_verbose "Cleaned: $log"
            fi
        done
        
        # Restart auditd
        if [ "$DRY_RUN" -eq 0 ]; then
            service auditd start 2>/dev/null || systemctl start auditd 2>/dev/null || true
        fi
    fi
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Audit logs cleaned ($count files)"
}

# Module: Linux Temporary Files
clean_linux_temp_files() {
    print_info "Cleaning temporary files..."
    local count=0

    # Find and remove suspicious patterns
    for dir in /tmp /var/tmp /dev/shm; do
        if [ -d "$dir" ]; then
            # Remove scripts and suspicious files
            find "$dir" -maxdepth 1 -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*script*" -o -name "*shell*" -o -name "*payload*" \) 2>/dev/null | while read -r file; do
                if safe_remove "$file"; then
                    count=$((count + 1))
                    print_verbose "Removed: $file"
                fi
            done
            
            # Remove hidden files (carefully)
            find "$dir" -maxdepth 1 -type f -name ".*" 2>/dev/null | while read -r file; do
                # Skip system files
                case "$file" in
                    */\.X*|*/\.ICE*|*/\.font*|*/systemd*) continue ;;
                    */\.*) 
                        if safe_remove "$file"; then
                            count=$((count + 1))
                            print_verbose "Removed: $file"
                        fi
                        ;;
                esac
            done
        fi
    done
    
    # Clean thumbnail caches for all users
    if [ "$(id -u)" -eq 0 ]; then
        local homes=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $6}' /etc/passwd)
        homes="$homes /root"
        for home in $homes; do
            if [ -d "$home/.cache/thumbnails" ]; then
                if [ "$DRY_RUN" -eq 0 ]; then
                    find "$home/.cache/thumbnails" -type f -delete 2>/dev/null || true
                fi
                count=$((count + 1))
                print_verbose "Cleaned thumbnail cache: $home/.cache/thumbnails"
            fi
        done
    else
        # Clean current user's thumbnails
        if [ -d "$HOME/.cache/thumbnails" ]; then
            if [ "$DRY_RUN" -eq 0 ]; then
                find "$HOME/.cache/thumbnails" -type f -delete 2>/dev/null || true
            fi
            count=$((count + 1))
            print_verbose "Cleaned thumbnail cache: $HOME/.cache/thumbnails"
        fi
    fi
    
    # Clean core dumps in safe locations
    for dir in /tmp /var/crash; do
        if [ -d "$dir" ]; then
            find "$dir" -name "core*" -type f -delete 2>/dev/null || true
            count=$((count + 1))
        fi
    done
    
    # Empty Users' Trash
    if [ "$(id -u)" -eq 0 ]; then
        local homes=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $6}' /etc/passwd)
        homes="$homes /root"
        for home in $homes; do
            if [ -d "$home/.local/share/Trash" ]; then
                if [ "$DRY_RUN" -eq 0 ]; then
                    rm -rf "$home/.local/share/Trash/files/"* 2>/dev/null || true
                    rm -rf "$home/.local/share/Trash/info/"* 2>/dev/null || true
                fi
                count=$((count + 1))
                print_verbose "Emptied trash: $home/.local/share/Trash"
            fi
        done
    else
        # Clean current user's trash
        if [ -d "$HOME/.local/share/Trash" ]; then
            if [ "$DRY_RUN" -eq 0 ]; then
                rm -rf "$HOME/.local/share/Trash/files/"* 2>/dev/null || true
                rm -rf "$HOME/.local/share/Trash/info/"* 2>/dev/null || true
            fi
            count=$((count + 1))
            print_verbose "Emptied trash: $HOME/.local/share/Trash"
        fi
    fi
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Temporary files cleaned ($count files)"
}

# Module: Linux Network Traces
clean_linux_network_traces() {
    print_info "Cleaning Linux network traces..."
    local count=0
    
    # Network-related logs
    for log in /var/log/daemon.log* /etc/NetworkManager/system-connections/*; do
        if truncate_file "$log"; then
            count=$((count + 1))
            print_verbose "Cleaned: $log"
        fi
    done
    
    # Clear ARP cache
    if [ "$DRY_RUN" -eq 0 ]; then
        ip neigh flush all 2>/dev/null || arp -d -a 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # Restart NetworkManager to reset traces
    if [ "$DRY_RUN" -eq 0 ]; then
        systemctl restart NetworkManager 2>/dev/null || service network-manager restart 2>/dev/null || true
    fi
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Network traces cleaned ($count items)"
}

# Module: Linux User Traces
clean_linux_user_traces() {
    print_info "Cleaning Linux user traces..."
    local count=0
    
    # Clean utmp (current logins)
    if truncate_file "/var/log/utmp"; then
        count=$((count + 1))
        print_verbose "Cleaned: /var/log/utmp"
    fi
    
    # Remove thumbnail caches and recent docs
    if [ "$(id -u)" -eq 0 ]; then
        local homes=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $6}' /etc/passwd)
        homes="$homes /root"
        for home in $homes; do
            # Old thumbnail location
            if [ -d "$home/.thumbnails" ]; then
                if [ "$DRY_RUN" -eq 0 ]; then
                    find "$home/.thumbnails" -type f -delete 2>/dev/null || true
                fi
                count=$((count + 1))
                print_verbose "Cleaned: $home/.thumbnails"
            fi
            
            # GNOME Tracker-3 Databases
            if [ "$DRY_RUN" -eq 0 ]; then
                rm -rf "$home/.cache/tracker"* 2>/dev/null || true
                rm -rf "$home/.local/state/tracker"* 2>/dev/null || true
            fi
            if [ -d "$home/.cache" ] || [ -d "$home/.local/state" ]; then
                count=$((count + 1))
                print_verbose "Cleaned GNOME Tracker: $home"
            fi
            
            # Zeitgeist Activity Logs
            if [ -d "$home/.local/share/zeitgeist" ]; then
                if [ "$DRY_RUN" -eq 0 ]; then
                    rm -rf "$home/.local/share/zeitgeist/"* 2>/dev/null || true
                fi
                count=$((count + 1))
                print_verbose "Cleaned Zeitgeist logs: $home/.local/share/zeitgeist"
            fi
        done
    else
        # Clean current user's old thumbnails
        if [ -d "$HOME/.thumbnails" ]; then
            if [ "$DRY_RUN" -eq 0 ]; then
                find "$HOME/.thumbnails" -type f -delete 2>/dev/null || true
            fi
            count=$((count + 1))
            print_verbose "Cleaned: $HOME/.thumbnails"
        fi
        
        # GNOME Tracker-3 Databases (current user)
        if [ "$DRY_RUN" -eq 0 ]; then
            rm -rf "$HOME/.cache/tracker"* 2>/dev/null || true
            rm -rf "$HOME/.local/state/tracker"* 2>/dev/null || true
        fi
        count=$((count + 1))
        print_verbose "Cleaned GNOME Tracker: $HOME"
        
        # Zeitgeist Activity Logs (current user)
        if [ -d "$HOME/.local/share/zeitgeist" ]; then
            if [ "$DRY_RUN" -eq 0 ]; then
                rm -rf "$HOME/.local/share/zeitgeist/"* 2>/dev/null || true
            fi
            count=$((count + 1))
            print_verbose "Cleaned Zeitgeist logs: $HOME/.local/share/zeitgeist"
        fi
    fi
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "User traces cleaned ($count items)"
}

# Module: macOS Specific
clean_macos_specific() {
    print_info "Cleaning macOS specific traces..."
    local count=0
    
    # Clean .DS_Store files
    if [ "$DRY_RUN" -eq 1 ]; then
        print_verbose "[DRY RUN] Would clean .DS_Store files"
        count=$((count + 1))
    else
        find / -name ".DS_Store" -type f -delete 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # Empty Trash for all users
    if [ "$(id -u)" -eq 0 ]; then
        find /Users -name ".Trash" -type d 2>/dev/null | while read -r trash; do
            rm -rf "$trash/*" 2>/dev/null || true
            count=$((count + 1))
            print_verbose "Emptied trash: $trash"
        done
    fi
    
    # Clean Spotlight
    if [ "$DRY_RUN" -eq 1 ]; then
        print_verbose "[DRY RUN] Would disable and clean Spotlight"
    else
        mdutil -E / >/dev/null 2>&1 || true
        rm -rf /.Spotlight-V100/* 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # Clean QuickLook thumbnails
    if [ "$DRY_RUN" -eq 0 ]; then
        qlmanage -r cache >/dev/null 2>&1 || true
        rm -rf /var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/* 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # Clean system logs
    for log in /var/log/system.log* /var/log/wifi.log* \
               /var/log/install.log* /var/log/accountpolicy.log* \
               /var/log/fsck* /var/log/powermanagement/* \
               /var/log/com.apple.xpc.launchd/* /var/log/asl/* \
               /var/log/appfirewall.log*; do
        if truncate_file "$log"; then
            count=$((count + 1))
            print_verbose "Cleaned: $log"
        fi
    done
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "macOS traces cleaned ($count items)"
}

# Module: macOS Audit Logs
clean_macos_audit_logs() {
    print_info "Cleaning macOS audit logs..."
    local count=0
    
    # Check if audit logs exist
    if [ -d "/var/audit" ]; then
        # Stop auditd temporarily
        if [ "$DRY_RUN" -eq 0 ]; then
            audit -t 2>/dev/null || true
        fi
        
        # Remove audit logs
        if [ "$DRY_RUN" -eq 0 ]; then
            rm -rf /var/audit/* 2>/dev/null || true
            count=$((count + 1))
            print_verbose "Cleaned audit logs: /var/audit"
        fi
        
        # Restart auditd
        if [ "$DRY_RUN" -eq 0 ]; then
            audit -s 2>/dev/null || true
        fi
    fi
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Audit logs cleaned ($count items)"
}

# Module: macOS Browser Traces
clean_macos_browser_traces() {
    print_info "Cleaning macOS browser traces..."
    local count=0
    
    # Get all user home directories
    local homes
    if [ "$(id -u)" -eq 0 ]; then
        homes=$(find /Users -maxdepth 1 -type d -not -path "/Users" -not -path "/Users/Shared" -not -path "/Users/Guest")
    else
        homes="$HOME"
    fi
    
    for home in $homes; do
        # Safari History & Cache
        if [ -f "$home/Library/Safari/History.db" ]; then
            if [ "$DRY_RUN" -eq 0 ]; then
                rm -f "$home/Library/Safari/History.db" 2>/dev/null || true
                count=$((count + 1))
                print_verbose "Cleaned Safari history: $home"
            fi
        fi
        
        if [ -d "$home/Library/Caches/com.apple.Safari" ]; then
            if [ "$DRY_RUN" -eq 0 ]; then
                rm -rf "$home/Library/Caches/com.apple.Safari/"* 2>/dev/null || true
                count=$((count + 1))
                print_verbose "Cleaned Safari cache: $home"
            fi
        fi
    done
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Browser traces cleaned ($count items)"
}

# Module: macOS Unified Logs
clean_macos_unified_logs() {
    print_info "Cleaning macOS unified logs..."
    local count=0
    
    # Check macOS version (unified logs are 10.12+)
    local macos_version=$(sw_vers -productVersion 2>/dev/null)
    # Simple string comparison without bc dependency
    case "$macos_version" in
        10.[1-9][2-9]*|1[1-9]*|[2-9][0-9]*)
        # Remove unified log files
        for dir in /var/db/diagnostics/Persist /var/db/diagnostics/Special \
                   /var/db/diagnostics/HighVolume /var/db/diagnostics/timesync; do
            if [ -d "$dir" ]; then
                rm -rf "$dir/*" 2>/dev/null || true
                count=$((count + 1))
                print_verbose "Cleaned unified logs: $dir"
            fi
        done
        
        # Purge log archives if log command is available
        if command -v log >/dev/null 2>&1 && [ "$DRY_RUN" -eq 0 ]; then
            log erase --all 2>/dev/null || true
            count=$((count + 1))
        fi
        ;;
    esac
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Unified logs cleaned ($count items)"
}

# Module: macOS File Events
clean_macos_file_events() {
    print_info "Cleaning macOS file events..."
    local count=0
    
    # Clean FSEvents
    find / -name ".fseventsd" -type d 2>/dev/null | while read -r fsevent_dir; do
        rm -rf "$fsevent_dir/*" 2>/dev/null || true
        count=$((count + 1))
        print_verbose "Cleaned FSEvents: $fsevent_dir"
    done
    
    # Clean quarantine database (system-wide)
    local quarantine_db="/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
    if [ -f "$quarantine_db" ] && [ "$DRY_RUN" -eq 0 ]; then
        sqlite3 "$quarantine_db" "DELETE FROM LSQuarantineEvent; VACUUM;" 2>/dev/null || true
        count=$((count + 1))
        print_verbose "Cleaned quarantine database"
    fi
    
    # Clean user quarantine databases
    local homes
    if [ "$(id -u)" -eq 0 ]; then
        homes=$(find /Users -maxdepth 1 -type d -not -path "/Users" -not -path "/Users/Shared" -not -path "/Users/Guest")
    else
        homes="$HOME"
    fi
    
    for home in $homes; do
        local user_quarantine="$home/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        if [ -f "$user_quarantine" ] && [ "$DRY_RUN" -eq 0 ]; then
            sqlite3 "$user_quarantine" "DELETE FROM LSQuarantineEvent; VACUUM;" 2>/dev/null || true
            count=$((count + 1))
            print_verbose "Cleaned user quarantine database: $home"
        fi
    done
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "File events cleaned ($count items)"
}

# Module: macOS Usage Traces
clean_macos_usage_traces() {
    print_info "Cleaning macOS usage traces..."
    local count=0
    
    # Clean KnowledgeC database (app usage)
    local knowledge_db="/private/var/db/CoreDuet/Knowledge/knowledgeC.db"
    if [ -f "$knowledge_db" ] && [ "$DRY_RUN" -eq 0 ]; then
        sqlite3 "$knowledge_db" "DELETE FROM ZSTRUCTUREDMETADATA; VACUUM;" 2>/dev/null || true
        count=$((count + 1))
        print_verbose "Cleaned KnowledgeC database"
    fi
    
    # Clean Notification Center
    find /private/var/folders -name "com.apple.notificationcenter" -type d 2>/dev/null | while read -r nc_dir; do
        rm -rf "$nc_dir/db2/db*" 2>/dev/null || true
        count=$((count + 1))
        print_verbose "Cleaned Notification Center: $nc_dir"
    done
    
    # Clean recent items
    if [ "$DRY_RUN" -eq 0 ]; then
        defaults delete com.apple.recentitems RecentDocuments 2>/dev/null || true
        defaults delete com.apple.recentitems RecentApplications 2>/dev/null || true
        defaults delete com.apple.recentitems RecentServers 2>/dev/null || true
        count=$((count + 1))
    fi
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Usage traces cleaned ($count items)"
}

# Module: Windows Event Logs
clean_windows_event_logs() {
    print_info "Cleaning Windows event logs..."
    local count=0
    
    # Clear main event logs
    for log in Application System Security Setup ForwardedEvents; do
        if [ "$DRY_RUN" -eq 1 ]; then
            print_verbose "[DRY RUN] Would clear event log: $log"
            count=$((count + 1))
        else
            wevtutil cl "$log" 2>/dev/null && count=$((count + 1)) || true
        fi
    done
    
    # Clear PowerShell logs
    for log in "Microsoft-Windows-PowerShell/Operational" \
               "Windows PowerShell" \
               "Microsoft-Windows-Sysmon/Operational" \
               "Microsoft-Windows-TaskScheduler/Operational" \
               "Microsoft-Windows-AppLocker/EXE and DLL" \
               "Microsoft-Windows-WinRM/Operational"; do
        if [ "$DRY_RUN" -eq 1 ]; then
            print_verbose "[DRY RUN] Would clear event log: $log"
            count=$((count + 1))
        else
            wevtutil cl "$log" 2>/dev/null && count=$((count + 1)) || true
        fi
    done
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Event logs cleaned ($count logs)"
}

# Module: Windows History
clean_windows_history() {
    print_info "Cleaning Windows history..."
    local count=0
    
    # PowerShell history
    local ps_history="$APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if truncate_file "$ps_history"; then
        count=$((count + 1))
        print_verbose "Cleaned PowerShell history"
    fi
    
    # Clear command prompt history
    if [ "$DRY_RUN" -eq 0 ]; then
        doskey /reinstall >/dev/null 2>&1 || true
        count=$((count + 1))
    fi
    
    # Clear Run dialog history
    if [ "$DRY_RUN" -eq 1 ]; then
        print_verbose "[DRY RUN] Would clear Run dialog history"
        count=$((count + 1))
    else
        reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # Clear prefetch and Superfetch/ReadyBoot
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -f /Windows/Prefetch/*.pf 2>/dev/null || true
        rm -f /Windows/Prefetch/ReadyBoot/*.etl 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # Clear LNK files
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -f "$APPDATA/Microsoft/Windows/Recent/*.lnk" 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # Clear Jump Lists
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -f "$APPDATA/Microsoft/Windows/Recent/AutomaticDestinations/*" 2>/dev/null || true
        rm -f "$APPDATA/Microsoft/Windows/Recent/CustomDestinations/*" 2>/dev/null || true
        count=$((count + 1))
    fi
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Windows history cleaned ($count items)"
}

# Module: Windows Registry MRUs
clean_windows_registry() {
    print_info "Cleaning Windows registry MRUs..."
    local count=0
    
    # List of MRU registry keys to clean
    local mru_keys="
    HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
    HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
    HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
    HKCU\Software\Microsoft\Office\*\*\File MRU
    HKCU\Software\Microsoft\Office\*\*\Place MRU
    HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
    HKCU\Software\Microsoft\Windows\Shell\Bags
    HKCU\Software\Microsoft\Windows\Shell\BagMRU
    HKCU\Software\Microsoft\Windows\ShellNoRoam\Bags
    HKCU\Software\Microsoft\Windows\ShellNoRoam\BagMRU
    HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags
    HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
    HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
    "
    
    for key in $mru_keys; do
        if [ "$DRY_RUN" -eq 1 ]; then
            print_verbose "[DRY RUN] Would clear registry key: $key"
            count=$((count + 1))
        else
            reg delete "$key" /va /f 2>/dev/null && count=$((count + 1)) || true
        fi
    done
    
    # USB history
    if [ "$DRY_RUN" -eq 0 ]; then
        reg delete 'HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR' /f 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # Mounted devices
    if [ "$DRY_RUN" -eq 0 ]; then
        reg delete 'HKLM\SYSTEM\MountedDevices' /va /f 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # BAM (Background Activity Monitor)
    if [ "$DRY_RUN" -eq 0 ]; then
        reg delete 'HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' /f 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # ShimCache/AppCompat
    if [ "$DRY_RUN" -eq 0 ]; then
        reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' /va /f 2>/dev/null || true
        count=$((count + 1))
    fi
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Registry MRUs cleaned ($count keys)"
}

# Module: Windows File System Traces
clean_windows_filesystem_traces() {
    print_info "Cleaning Windows file system traces..."
    local count=0
    
    # Get list of drives dynamically
    local drives=""
    if command -v wmic >/dev/null 2>&1; then
        drives=$(wmic logicaldisk get name 2>/dev/null | grep -E '^[A-Z]:' | tr -d ':\r\n' | sed 's/./& /g')
    else
        # Fallback to common drives if wmic not available
        drives="C D E F G H"
    fi
    
    # Clean USN Journal
    if [ "$DRY_RUN" -eq 0 ]; then
        for drive in $drives; do
            fsutil usn deletejournal /D $drive: 2>/dev/null || true
        done
        count=$((count + 1))
    fi
    
    # Empty Recycle Bin
    if [ "$DRY_RUN" -eq 0 ]; then
        for drive in $drives; do
            rd /s /q $drive:\$Recycle.Bin 2>/dev/null || true
        done
        count=$((count + 1))
    fi
    
    # Clean thumbcache
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -f "$USERPROFILE/AppData/Local/Microsoft/Windows/Explorer/thumbcache_*.db" 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # Clean SRUDB
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -f "C:/Windows/System32/sru/SRUDB.dat" 2>/dev/null || true
        count=$((count + 1))
    fi
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "File system traces cleaned ($count items)"
}

# Module: Windows Temporary Files
clean_windows_temp_files() {
    print_info "Cleaning Windows temporary files..."
    local count=0
    
    # Remove temps
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -rf "$TEMP/*" 2>/dev/null || true
        rm -rf "C:/Windows/Temp/*" 2>/dev/null || true
        rm -f "C:/Windows/Prefetch/*.tmp" 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # Clear DNS cache
    if [ "$DRY_RUN" -eq 0 ]; then
        ipconfig /flushdns 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # Clear Volume Shadow Copies (with warning)
    if [ "$DRY_RUN" -eq 0 ]; then
        print_verbose "WARNING: Removing Volume Shadow Copies will delete restore points"
        vssadmin delete shadows /all /quiet 2>/dev/null || true
        count=$((count + 1))
    fi
    
    # Windows Error Reporting archives
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -rf "C:/ProgramData/Microsoft/Windows/WER/ReportArchive/"* 2>/dev/null || true
        rm -rf "C:/ProgramData/Microsoft/Windows/WER/ReportQueue/"* 2>/dev/null || true
        rm -rf "$LOCALAPPDATA/Microsoft/Windows/WER/ReportArchive/"* 2>/dev/null || true
        rm -rf "$LOCALAPPDATA/Microsoft/Windows/WER/ReportQueue/"* 2>/dev/null || true
        count=$((count + 1))
        print_verbose "Cleaned Windows Error Reporting archives"
    fi
    
    # Crash dumps
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -rf "C:/Windows/Minidump/"* 2>/dev/null || true
        rm -f "C:/Windows/MEMORY.DMP" 2>/dev/null || true
        count=$((count + 1))
        print_verbose "Cleaned crash dumps"
    fi
    
    # Memory residue hardening (optional - requires reboot to take effect)
    if [ "$ADVANCED" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
        # Disable hibernation (removes hiberfil.sys)
        powercfg -h off 2>/dev/null || true
        # Enable pagefile clearing at shutdown
        reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f 2>/dev/null || true
        count=$((count + 1))
        print_verbose "Enabled memory residue hardening (requires reboot)"
    fi
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Temporary files cleaned ($count items)"
}

# Run cleaning modules based on OS
run_cleaners() {
    case "$OS_TYPE" in
        linux)
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "shell"; then
                clean_linux_shell_history
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "logs"; then
                clean_linux_system_logs
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "audit"; then
                clean_linux_audit_logs
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "temp"; then
                clean_linux_temp_files
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "network"; then
                clean_linux_network_traces
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "user"; then
                clean_linux_user_traces
            fi
            ;;
        macos)
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "shell"; then
                clean_linux_shell_history  # macOS uses same shell history
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "macos"; then
                clean_macos_specific
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "audit"; then
                clean_macos_audit_logs
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "browser"; then
                clean_macos_browser_traces
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "unified"; then
                clean_macos_unified_logs
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "fileevents"; then
                clean_macos_file_events
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "usage"; then
                clean_macos_usage_traces
            fi
            ;;
        windows)
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "events"; then
                clean_windows_event_logs
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "history"; then
                clean_windows_history
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "registry"; then
                clean_windows_registry
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "filesystem"; then
                clean_windows_filesystem_traces
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "temp"; then
                clean_windows_temp_files
            fi
            ;;
    esac
}

# List available modules
list_modules() {
    echo "Available cleaning modules:"
    echo ""
    case "$OS_TYPE" in
        linux)
            echo "  shell    - Shell history files (.bash_history, etc.)"
            echo "  logs     - System logs (/var/log/*)"
            echo "  audit    - Audit logs (auditd)"
            echo "  temp     - Temporary suspicious files (/tmp/*)"
            echo "  network  - Network traces (ARP cache, NetworkManager)"
            echo "  user     - User traces (thumbnails, utmp)"
            ;;
        macos)
            echo "  shell      - Shell history files"
            echo "  macos      - macOS specific traces (.DS_Store, Spotlight, etc.)"
            echo "  audit      - Audit (BSM) logs"
            echo "  browser    - Safari history and cache"
            echo "  unified    - Unified logs (10.12+)"
            echo "  fileevents - FSEvents and quarantine database"
            echo "  usage      - App usage traces (KnowledgeC, notifications)"
            ;;
        windows)
            echo "  events     - Windows Event Logs (including Sysmon, WinRM)"
            echo "  history    - PowerShell/CMD history, prefetch, jump lists"
            echo "  registry   - Registry MRUs, USB history, BAM"
            echo "  filesystem - USN journal, recycle bin, thumbcache"
            echo "  temp       - Temporary files, DNS cache, shadow copies"
            ;;
    esac
    echo ""
}

# Show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help        Show this help message"
    echo "  -v, --version     Show version"
    echo "  -n, --dry-run     Perform a dry run (no changes)"
    echo "  -d, --debug       Enable verbose output"
    echo "  -l, --list        List available modules"
    echo "  -m, --modules     Comma-separated list of modules to run"
    echo "  -f, --force       Skip confirmation prompt"
    echo "  -a, --advanced    Also wipe hiberfil.sys and zero pagefile on shutdown"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run all modules (interactive)"
    echo "  $0 -n                 # Dry run to see what would be cleaned"
    echo "  $0 -m shell,logs      # Clean only shell history and logs"
    echo "  $0 -f                 # Force run without confirmation"
    echo ""
}

# Parse command line arguments
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                echo "Nyx v${VERSION}"
                exit 0
                ;;
            -n|--dry-run)
                DRY_RUN=1
                ;;
            -d|--debug)
                VERBOSE=1
                ;;
            -l|--list)
                detect_os
                list_modules
                exit 0
                ;;
            -m|--modules)
                shift
                MODULES="$1"
                ;;
            -f|--force)
                FORCE=1
                ;;
            -a|--advanced)
                ADVANCED=1
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done
}

# Confirmation prompt
confirm_action() {
    if [ "${FORCE:-0}" -eq 1 ]; then
        return 0
    fi
    
    if [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi
    
    printf "Do you want to continue? [y/N]: "
    read -r response
    case "$response" in
        [yY][eE][sS]|[yY])
            return 0
            ;;
        *)
            echo "Aborted."
            exit 0
            ;;
    esac
}

# Summary report
print_summary() {
    echo ""
    echo "${GREEN}================================================${NC}"
    echo "${GREEN}              Cleaning Complete!${NC}"
    echo "${GREEN}================================================${NC}"
    echo ""
    echo "Summary:"
    echo "  Total items cleaned: ${CLEANED_COUNT}"
    echo "  Failed operations: ${FAILED_COUNT}"
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo ""
        echo "${YELLOW}This was a dry run. No actual changes were made.${NC}"
    fi
    echo ""
}

# Main function
main() {
    # Parse arguments first
    parse_args "$@"
    
    # Show banner
    print_banner
    
    # Detect OS
    detect_os
    
    # Show warning
    print_warning
    
    # Check privileges (unless listing modules or dry run)
    if [ "$DRY_RUN" -eq 0 ]; then
        check_privileges
    fi
    
    # Confirm action
    confirm_action
    
    # Show mode
    if [ "$DRY_RUN" -eq 1 ]; then
        print_info "Running in DRY RUN mode - no changes will be made"
    fi
    
    print_info "Operating System: ${OS_TYPE}"
    print_info "Modules: ${MODULES:-all}"
    echo ""
    
    # Run cleaners
    run_cleaners
    
    # Show summary
    print_summary
}

# Run main function
main "$@"
