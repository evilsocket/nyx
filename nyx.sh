#!/bin/sh
# Nyx - Cross-platform anti-forensics trace cleaner
# Developed by Simone Margaritelli <evilsocket@gmail.com>
# Released under the GPLv3 license.
set -eu
# Enable pipefail if supported (bash extension, not POSIX)
if (set -o pipefail 2>/dev/null); then
    set -o pipefail
fi

# Global variables
VERSION="1.0.0-alpha"
DRY_RUN=0
VERBOSE=0
MODULES=""
OS_TYPE=""
RESULTS=""
CLEANED_COUNT=0
FAILED_COUNT=0
LOGFILE=""

# Trap SIGINT for cleanup
trap 'echo "
Operation interrupted by user"; exit 130' INT

# Color codes (disabled if not TTY, respecting NO_COLOR)
if [ -t 1 ] && [ "${TERM:-}" != "dumb" ] && [ -z "${NO_COLOR:-}" ]; then
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

# Setup logging if specified
setup_logging() {
    if [ -n "${LOGFILE:-}" ]; then
        exec 3>>"$LOGFILE" || {
            printf '[ERROR] Failed to open log file: %s\n' "$LOGFILE" >&2
            exit 1
        }
    fi
}

# Log function
log_message() {
    if [ -n "$LOGFILE" ]; then
        printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >&3
    fi
}

# Print functions
print_banner() {
    echo "${BLUE}================================================${NC}"
    echo "${BLUE}              Nyx v${VERSION}${NC}"
    echo "${BLUE}      Anti-Forensics Trace Cleaner${NC}"
    echo "${BLUE}================================================${NC}"
    echo ""
    log_message "Nyx v${VERSION} started"
}

print_warning() {
    local msg="⚠️  WARNING: This tool will permanently delete forensic traces!"
    local msg2="This action cannot be undone and may impact system stability."
    echo "${YELLOW}${msg}${NC}"
    echo "${YELLOW}${msg2}${NC}"
    echo ""
    log_message "WARNING: ${msg}"
    log_message "WARNING: ${msg2}"
}

print_error() {
    local msg="[ERROR] $1"
    echo "${RED}${msg}${NC}" >&2
    log_message "ERROR: $1"
}

print_success() {
    local msg="[✓] $1"
    echo "${GREEN}${msg}${NC}"
    log_message "SUCCESS: $1"
}

print_info() {
    local msg="[*] $1"
    echo "${BLUE}${msg}${NC}"
    log_message "INFO: $1"
}

print_verbose() {
    if [ "$VERBOSE" -eq 1 ]; then
        local msg="[DEBUG] $1"
        echo "$msg"
        log_message "DEBUG: $1"
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
        *)          
            print_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac
    
    print_verbose "Detected OS: $OS_TYPE"
}

# Check if running as root/admin
check_privileges() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "This script must be run as root"
        echo "Try: sudo $0 $*"
        exit 1
    fi
}

# Safe file operations
safe_remove() {
    local file="$1"
    if [ -f "$file" ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            print_verbose "[DRY RUN] Would remove: $file"
            return 0
        else
            if rm -f -- "$file" 2>/dev/null; then
                return 0
            else
                FAILED_COUNT=$((FAILED_COUNT + 1))
                return 1
            fi
        fi
    fi
    return 1
}

safe_remove_tree() {
    local path="$1"
    if [ -d "$path" ] || [ -f "$path" ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            print_verbose "[DRY RUN] Would remove tree: $path"
            return 0
        else
            if rm -rf -- "$path" 2>/dev/null; then
                return 0
            else
                FAILED_COUNT=$((FAILED_COUNT + 1))
                return 1
            fi
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
            if > "$file" 2>/dev/null; then
                return 0
            else
                FAILED_COUNT=$((FAILED_COUNT + 1))
                return 1
            fi
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
        # Delete in-kernel audit rules first if auditctl is available
        if command -v auditctl >/dev/null 2>&1 && [ "$DRY_RUN" -eq 0 ]; then
            auditctl -D 2>/dev/null || true
            print_verbose "Deleted in-kernel audit rules"
        fi
        
        # Stop auditd temporarily
        if [ "$DRY_RUN" -eq 0 ]; then
            if command -v systemctl >/dev/null 2>&1; then
                systemctl stop auditd 2>/dev/null || true
            elif command -v service >/dev/null 2>&1; then
                service auditd stop 2>/dev/null || true
            fi
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
            if command -v systemctl >/dev/null 2>&1; then
                systemctl start auditd 2>/dev/null || true
            elif command -v service >/dev/null 2>&1; then
                service auditd start 2>/dev/null || true
            fi
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
    
    # Clean core dumps and crash reports in safe locations
    for dir in /tmp /var/crash; do
        if [ -d "$dir" ]; then
            find "$dir" \( -name "core*" -o -name "*.crash" -o -name "*crash*" \) -type f -delete 2>/dev/null || true
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
    
    # Network-related logs including journal remote and private
    for log in /var/log/daemon.log* /var/log/journal/remote/* /var/log/private/*; do
        if truncate_file "$log"; then
            count=$((count + 1))
            print_verbose "Cleaned: $log"
        fi
    done
    
    # Clean systemd-coredump logs if present
    if [ -d "/var/lib/systemd/coredump" ]; then
        if [ "$DRY_RUN" -eq 0 ]; then
            # Remove individual files in the coredump directory
            for coredump in /var/lib/systemd/coredump/*; do
                if [ -f "$coredump" ] || [ -d "$coredump" ]; then
                    safe_remove_tree "$coredump"
                fi
            done
            count=$((count + 1))
            print_verbose "Cleaned systemd-coredump logs"
        else
            print_verbose "[DRY RUN] Would clean systemd-coredump logs"
            count=$((count + 1))
        fi
    fi
    
    # Remove NetworkManager connections
    if [ -d "/etc/NetworkManager/system-connections" ]; then
        for conn in /etc/NetworkManager/system-connections/*; do
            if [ -f "$conn" ]; then
                if safe_remove "$conn"; then
                    count=$((count + 1))
                    print_verbose "Removed NetworkManager connection: $conn"
                fi
            fi
        done
        
        # Reload NetworkManager instead of full restart to avoid dropping DHCP leases
        if [ "$DRY_RUN" -eq 0 ] && command -v nmcli >/dev/null 2>&1; then
            nmcli connection reload 2>/dev/null || true
            print_verbose "Reloaded NetworkManager connections"
        fi
    fi
    
    # Clear ARP cache
    if [ "$DRY_RUN" -eq 0 ]; then
        if command -v ip >/dev/null 2>&1; then
            ip neigh flush all 2>/dev/null || true
        elif command -v arp >/dev/null 2>&1; then
            arp -d -a 2>/dev/null || true
        fi
        count=$((count + 1))
    fi
    
    # Clean DHCP leases
    for dhcp_lease in /var/lib/dhclient/*.leases /var/lib/dhcp/*.leases; do
        if safe_remove "$dhcp_lease"; then
            count=$((count + 1))
            print_verbose "Cleaned DHCP lease: $dhcp_lease"
        fi
    done
    
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
            
            # GTK bookmarks
            if truncate_file "$home/.config/gtk-3.0/bookmarks"; then
                count=$((count + 1))
                print_verbose "Cleaned GTK bookmarks: $home"
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
            
            # Editor/IDE traces
            for editor_path in "$home/.local/share/code-server/User" "$home/.config/Code/User" "$home/.local/share/code/Backups"; do
                if safe_remove_tree "$editor_path"; then
                    count=$((count + 1))
                    print_verbose "Cleaned editor traces: $editor_path"
                fi
            done
            
            # JetBrains IDE logs (handle wildcard expansion)
            for intellij_dir in "$home/.local/share/.IntelliJIdea"*; do
                if [ -d "$intellij_dir/system/log" ]; then
                    for log_file in "$intellij_dir/system/log/"*; do
                        if truncate_file "$log_file"; then
                            count=$((count + 1))
                            print_verbose "Cleaned JetBrains log: $log_file"
                        fi
                    done
                fi
            done
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
        
        # GTK bookmarks (current user)
        if truncate_file "$HOME/.config/gtk-3.0/bookmarks"; then
            count=$((count + 1))
            print_verbose "Cleaned GTK bookmarks: $HOME"
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
        
        # Editor/IDE traces (current user)
        for editor_path in "$HOME/.local/share/code-server/User" "$HOME/.config/Code/User" "$HOME/.local/share/.IntelliJIdea*/system/log" "$HOME/.local/share/code/Backups"; do
            if safe_remove_tree "$editor_path"; then
                count=$((count + 1))
                print_verbose "Cleaned editor traces: $editor_path"
            fi
        done
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

# Extended Module: Linux Package Manager Artifacts
clean_linux_package_artifacts() {
    print_info "Cleaning Linux package manager artifacts..."
    local count=0
    
    # APT/DPKG artifacts
    if command -v apt >/dev/null 2>&1 || command -v dpkg >/dev/null 2>&1; then
        for path in /var/cache/apt/archives/* /var/log/apt/* /var/log/dpkg.log*; do
            if safe_remove_tree "$path"; then
                count=$((count + 1))
                print_verbose "Cleaned APT/DPKG: $path"
            fi
        done
    fi
    
    # YUM/DNF artifacts
    if command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
        for path in /var/cache/yum/* /var/cache/dnf/* /var/log/yum.log* /var/log/dnf.log*; do
            if safe_remove_tree "$path"; then
                count=$((count + 1))
                print_verbose "Cleaned YUM/DNF: $path"
            fi
        done
    fi
    
    # Pacman artifacts (clean regardless of pacman availability)
    for path in /var/cache/pacman/pkg/* /var/log/pacman.log*; do
        if safe_remove_tree "$path"; then
            count=$((count + 1))
            print_verbose "Cleaned Pacman: $path"
        fi
    done
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Package manager artifacts cleaned ($count items)"
}

# Extended Module: Linux Browser Traces
clean_linux_browser_traces() {
    print_info "Cleaning Linux browser traces..."
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
            # Firefox artifacts
            for firefox_dir in "$home/.mozilla/firefox/"*".default-release" "$home/.mozilla/firefox/"*".default"; do
                if [ -d "$firefox_dir" ]; then
                    for artifact in cache2 storage thumbnails sessionstore-backups; do
                        if safe_remove_tree "$firefox_dir/$artifact"; then
                            count=$((count + 1))
                            print_verbose "Cleaned Firefox $artifact: $home"
                        fi
                    done
                    # Clean specific files
                    for file in places.sqlite cookies.sqlite formhistory.sqlite; do
                        if safe_remove "$firefox_dir/$file"; then
                            count=$((count + 1))
                            print_verbose "Cleaned Firefox $file: $home"
                        fi
                    done
                fi
            done
            
            # Chrome/Chromium artifacts
            for chrome_dir in "$home/.config/google-chrome/Default" "$home/.config/chromium/Default"; do
                if [ -d "$chrome_dir" ]; then
                    for artifact in Cache History Cookies "Web Data" "Top Sites"; do
                        if safe_remove_tree "$chrome_dir/$artifact"; then
                            count=$((count + 1))
                            print_verbose "Cleaned Chrome/Chromium $artifact: $home"
                        fi
                    done
                fi
            done
        fi
    done
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Browser traces cleaned ($count items)"
}

# Extended Module: Linux SSH Traces  
clean_linux_ssh_traces() {
    print_info "Cleaning Linux SSH traces..."
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
        if [ -d "$home/.ssh" ]; then
            # Clean known_hosts
            if truncate_file "$home/.ssh/known_hosts"; then
                count=$((count + 1))
                print_verbose "Cleaned SSH known_hosts: $home"
            fi
            
            # Clean any SSH log files
            for ssh_log in "$home/.ssh/"*.log; do
                if safe_remove "$ssh_log"; then
                    count=$((count + 1))
                    print_verbose "Cleaned SSH log: $ssh_log"
                fi
            done
        fi
    done
    
    # Clean system SSH logs from auth.log/secure
    for log in /var/log/auth.log* /var/log/secure*; do
        if [ -f "$log" ] && [ "$DRY_RUN" -eq 0 ]; then
            # Remove SSH-specific entries while preserving other auth logs
            sed -i '/sshd\[/d' "$log" 2>/dev/null || true
            count=$((count + 1))
            print_verbose "Cleaned SSH entries from: $log"
        fi
    done
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "SSH traces cleaned ($count items)"
}

# Extended Module: Linux Container Traces
clean_linux_container_traces() {
    print_info "Cleaning Linux container traces..."
    local count=0
    
    # Docker artifacts (clean regardless of docker availability)
    # Clean Docker logs
    for docker_log in /var/lib/docker/containers/*/*.log; do
        if truncate_file "$docker_log"; then
            count=$((count + 1))
            print_verbose "Cleaned Docker log: $docker_log"
        fi
    done
    
    # Clean user Docker config
    local homes
    if [ "$(id -u)" -eq 0 ]; then
        homes=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $6}' /etc/passwd)
        homes="$homes /root"
    else
        homes="$HOME"
    fi
    
    for home in $homes; do
        for docker_config in "$home/.docker/config.json" "$home/.docker/machine"; do
            if safe_remove_tree "$docker_config"; then
                count=$((count + 1))
                print_verbose "Cleaned Docker config: $docker_config"
            fi
        done
    done
    
    # Podman/K8s artifacts (clean regardless of podman availability)
    for podman_log in /var/lib/containers/*/overlay/*/userdata /var/log/pods/*; do
        if safe_remove_tree "$podman_log"; then
            count=$((count + 1))
            print_verbose "Cleaned Podman/K8s: $podman_log"
        fi
    done
    
    # Libvirt/QEMU artifacts (clean regardless of virsh availability)
    for libvirt_path in /var/log/libvirt/qemu/* /var/cache/libvirt/qemu/*; do
        if safe_remove_tree "$libvirt_path"; then
            count=$((count + 1))
            print_verbose "Cleaned libvirt: $libvirt_path"
        fi
    done
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Container traces cleaned ($count items)"
}

# Extended Module: Additional systemd artifacts
clean_linux_systemd_extra() {
    print_info "Cleaning additional systemd artifacts..."
    local count=0
    
    # Random seed file
    if safe_remove "/var/lib/systemd/random-seed"; then
        count=$((count + 1))
        print_verbose "Cleaned systemd random-seed"
    fi
    
    # Live-session journal traces
    for journal_dir in /run/log/journal/*; do
        if safe_remove_tree "$journal_dir"; then
            count=$((count + 1))
            print_verbose "Cleaned live-session journal: $journal_dir"
        fi
    done
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Additional systemd artifacts cleaned ($count items)"
}

# Extended Module: Print subsystem
clean_linux_print_traces() {
    print_info "Cleaning print subsystem traces..."
    local count=0
    
    # CUPS job history and logs
    for cups_path in /var/spool/cups/* /var/log/cups/*; do
        if safe_remove_tree "$cups_path"; then
            count=$((count + 1))
            print_verbose "Cleaned CUPS: $cups_path"
        fi
    done
    
    CLEANED_COUNT=$((CLEANED_COUNT + count))
    print_success "Print subsystem traces cleaned ($count items)"
}

# Run cleaning modules based on OS
run_cleaners() {
    case "$OS_TYPE" in
        linux)
            # Basic modules
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
            
            # Extended modules
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "package"; then
                clean_linux_package_artifacts
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "browser"; then
                clean_linux_browser_traces
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "ssh"; then
                clean_linux_ssh_traces
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "container"; then
                clean_linux_container_traces
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "systemd"; then
                clean_linux_systemd_extra
            fi
            if [ -z "$MODULES" ] || echo "$MODULES" | grep -q "print"; then
                clean_linux_print_traces
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
    esac
}

# List available modules
list_modules() {
    echo "Available cleaning modules:"
    echo ""
    case "$OS_TYPE" in
        linux)
            echo "Basic modules:"
            echo "  shell    - Shell history files (.bash_history, etc.)"
            echo "  logs     - System logs (/var/log/*)"
            echo "  audit    - Audit logs (auditd)"
            echo "  temp     - Temporary suspicious files (/tmp/*)"
            echo "  network  - Network traces (ARP cache, NetworkManager)"
            echo "  user     - User traces (thumbnails, utmp)"
            echo ""
            echo "Extended modules:"
            echo "  package  - Package manager artifacts (apt, yum, pacman)"
            echo "  container- Container/VM logs (Docker, Podman, libvirt)"
            echo "  browser  - Browser traces (Firefox, Chrome/Chromium)"
            echo "  ssh      - SSH operational traces and logs"
            echo "  print    - CUPS print subsystem logs"
            echo "  systemd  - Additional systemd artifacts"
            echo "  crash    - Crash dumps and core files"
            ;;
        macos)
            echo "Basic modules:"
            echo "  shell      - Shell history files"
            echo "  macos      - macOS specific traces (.DS_Store, Spotlight, etc.)"
            echo "  audit      - Audit (BSM) logs"
            echo "  browser    - Safari history and cache"
            echo "  unified    - Unified logs (10.12+)"
            echo "  fileevents - FSEvents and quarantine database"
            echo "  usage      - App usage traces (KnowledgeC, notifications)"
            echo ""
            echo "Extended modules:"
            echo "  macos-logs - Additional diagnostic and crash logs"
            echo "  macos-wifi - Wi-Fi and location traces"
            echo "  macos-brew - Homebrew artifacts"
            echo "  editor     - IDE and editor traces"
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
    echo ""
    echo "Examples:"
    echo "  $0                    # Run all modules (interactive)"
    echo "  $0 -n                 # Dry run to see what would be cleaned"
    echo "  $0 -m shell,logs      # Clean only shell history and logs"
    echo "  $0 -f                 # Force run without confirmation"
    echo ""
}

# Parse and clean module string
parse_modules() {
    if [ -n "$MODULES" ]; then
        # Convert to lowercase and remove whitespace
        MODULES=$(echo "$MODULES" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        print_verbose "Parsed modules: $MODULES"
    fi
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
            --logfile)
                shift
                LOGFILE="$1"
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
    
    # Setup logging if specified
    setup_logging
    
    # Show banner
    print_banner
    
    # Detect OS before list option
    detect_os
    
    # Show warning
    print_warning
    
    # Check privileges (unless listing modules or dry run)
    if [ "$DRY_RUN" -eq 0 ]; then
        check_privileges
    fi
    
    # Parse and validate modules
    parse_modules
    
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
    
    # Exit with appropriate code - only exit 1 for critical failures
    # Minor failures (file not found, etc.) are normal and shouldn't cause script failure
    if [ "$FAILED_COUNT" -gt 50 ]; then  # Only exit 1 if there are excessive failures
        print_error "Too many failed operations ($FAILED_COUNT), indicating serious issues"
        exit 1
    fi
}

# Run main function
main "$@"
