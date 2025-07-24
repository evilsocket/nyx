#!/bin/bash
# Script to verify forensic artifacts have been cleaned by Nyx

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo "================================"
echo "Verifying Artifact Cleanup"
echo "================================"
echo ""

# Counter for tracking failures
FAILED_CHECKS=0
PASSED_CHECKS=0

# Function to report failure and exit
fail() {
    echo -e "${RED}[✗] $1${NC}"
    echo -e "${RED}    Expected: $2${NC}"
    echo -e "${RED}    Found: $3${NC}"
    exit 1
}

# Function to report success
pass() {
    echo -e "${GREEN}[✓] $1${NC}"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
}

# Function to check if file is empty (size 0)
check_empty() {
    local file="$1"
    local desc="$2"
    
    if [ ! -f "$file" ]; then
        pass "$desc - File removed"
        return 0
    fi
    
    if [ ! -s "$file" ]; then
        pass "$desc - File empty"
        return 0
    else
        local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "unknown")
        fail "$desc" "Empty file (size 0)" "File exists with size $size bytes"
    fi
}

# Function to check if file/directory doesn't exist
check_not_exists() {
    local path="$1"
    local desc="$2"
    
    if [ ! -e "$path" ]; then
        pass "$desc - Removed"
        return 0
    else
        fail "$desc" "Path should not exist" "Path still exists"
    fi
}

# Function to check if directory is empty
check_dir_empty() {
    local dir="$1"
    local desc="$2"
    
    if [ ! -d "$dir" ]; then
        pass "$desc - Directory removed"
        return 0
    fi
    
    local count=$(find "$dir" -type f 2>/dev/null | wc -l)
    if [ "$count" -eq 0 ]; then
        pass "$desc - Directory empty"
        return 0
    else
        fail "$desc" "Empty directory" "Directory contains $count files"
    fi
}

# Function to check log doesn't contain marker
check_log_no_marker() {
    local log="$1"
    local marker="$2"
    local desc="$3"
    
    if [ ! -f "$log" ]; then
        pass "$desc - Log removed"
        return 0
    fi
    
    if ! sudo grep -q "$marker" "$log" 2>/dev/null; then
        pass "$desc - Marker '$marker' not found"
        return 0
    else
        local count=$(sudo grep -c "$marker" "$log" 2>/dev/null || echo "0")
        fail "$desc" "No '$marker' in log" "Found $count occurrences of '$marker'"
    fi
}

echo "[*] Checking shell history files..."

# Check all shell histories
check_empty ~/.bash_history "Bash history"
check_empty ~/.zsh_history "Zsh history"
check_empty ~/.sh_history "Shell history"
check_empty ~/.ash_history "Ash history"
check_empty ~/.fish_history "Fish history"
check_empty ~/.python_history "Python history"
check_empty ~/.mysql_history "MySQL history"
check_empty ~/.psql_history "PostgreSQL history"
check_empty ~/.sqlite_history "SQLite history"
check_empty ~/.rediscli_history "Redis CLI history"
check_empty ~/.lesshst "Less history"
check_empty ~/.viminfo "Vim info"
check_empty ~/.wget-hsts "Wget HSTS"
check_empty ~/.node_repl_history "Node REPL history"
check_empty ~/.Rhistory "R history"
check_empty ~/.gdb_history "GDB history"
check_empty ~/.mongo_history "MongoDB history"
check_empty ~/.docker_history "Docker history"

# Check .local/share histories
check_empty ~/.local/share/fish/fish_history "Fish local history"
check_empty ~/.local/share/recently-used.xbel "Recently used"
check_empty ~/.local/share/mc/history "Midnight Commander history"
check_empty ~/.local/share/nano/search_history "Nano search history"

echo ""
echo "[*] Checking system logs..."

# Check system logs for markers
check_log_no_marker /var/log/auth.log "10.0.0.1" "Auth log"
check_log_no_marker /var/log/syslog "NYX-TEST" "Syslog"
check_log_no_marker /var/log/syslog "UFW BLOCK" "Syslog (UFW)"
check_log_no_marker /var/log/kern.log "Process hiding" "Kernel log"

# Check Apache/Nginx logs
check_log_no_marker /var/log/apache2/access.log "admin/config.php" "Apache access"
check_log_no_marker /var/log/apache2/error.log "shell.php" "Apache error"
check_log_no_marker /var/log/nginx/access.log "upload.php" "Nginx access"

# Check audit logs
if [ -d "/var/log/audit" ]; then
    check_log_no_marker /var/log/audit/audit.log "NYXTEST" "Audit log"
    check_log_no_marker /var/log/audit/audit.log "nc -e /bin/bash" "Audit log (netcat)"
    check_log_no_marker /var/log/audit/ausearch.log "/bin/nc" "Audit search log"
fi

# Check login records
check_empty /var/log/wtmp "Login records (wtmp)"
check_empty /var/log/btmp "Failed logins (btmp)"
check_empty /var/log/lastlog "Last login"
check_empty /var/log/utmp "Current logins (utmp)"

# Check package manager logs
check_log_no_marker /var/log/dpkg.log "evilpkg" "DPKG log"
check_log_no_marker /var/log/dpkg.log "malicious-package" "DPKG log (malicious)"
check_log_no_marker /var/log/apt/history.log "netcat" "APT history"
check_log_no_marker /var/log/apt/term.log "netcat" "APT term log"

# Check cron logs
check_log_no_marker /var/log/cron "backdoor.sh" "Cron log"
check_log_no_marker /var/log/cron.log "c2server.com" "Cron log (alt)"

# Check mail logs
check_log_no_marker /var/log/mail.log "evil.com" "Mail log"
check_log_no_marker /var/log/maillog "attacker@evil.com" "Mail log (alt)"

# Check firewall logs
check_log_no_marker /var/log/ufw.log "DPT=4444" "UFW log"

# Check X11 logs
check_log_no_marker /var/log/Xorg.0.log "rootkit" "X11 log"

# Check CUPS logs
if [ -d "/var/log/cups" ]; then
    check_log_no_marker /var/log/cups/error_log "Suspicious print" "CUPS error log"
fi

# Check daemon logs
check_log_no_marker /var/log/daemon.log "NetworkManager" "Daemon log"

# Check journald for markers
if command -v journalctl >/dev/null 2>&1; then
    echo ""
    echo "[*] Checking journald logs..."
    
    if ! sudo journalctl --since "1 hour ago" | grep -q "NYX-TEST"; then
        pass "Journald - No NYX-TEST markers"
    else
        count=$(sudo journalctl --since "1 hour ago" | grep -c "NYX-TEST" || echo "0")
        fail "Journald" "No NYX-TEST markers" "Found $count NYX-TEST entries"
    fi
fi

echo ""
echo "[*] Checking temporary files..."

# Check temp files
check_not_exists /tmp/suspicious_script.sh "Suspicious script"
check_not_exists /tmp/.hidden_file "Hidden temp file"
check_not_exists /tmp/backdoor.py "Python backdoor"
check_not_exists /tmp/exploit.pl "Perl exploit"
check_not_exists /tmp/core.12345 "Core dump"

# Check for any suspicious temp files
SUSP_COUNT=$(find /tmp -maxdepth 1 -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*script*" -o -name "*shell*" -o -name "*payload*" \) 2>/dev/null | wc -l)
if [ "$SUSP_COUNT" -eq 0 ]; then
    pass "No suspicious scripts in /tmp"
else
    fail "Temp directory scripts" "No suspicious scripts" "Found $SUSP_COUNT suspicious files"
fi

# Check hidden files in temp
HIDDEN_COUNT=$(find /tmp -maxdepth 1 -type f -name ".*" 2>/dev/null | grep -v -E '(\.X|\.ICE|\.font|systemd)' | wc -l)
if [ "$HIDDEN_COUNT" -eq 0 ]; then
    pass "No hidden files in /tmp"
else
    fail "Hidden temp files" "No hidden files" "Found $HIDDEN_COUNT hidden files"
fi

echo ""
echo "[*] Checking user traces..."

# Check thumbnail caches
check_dir_empty ~/.cache/thumbnails "Thumbnail cache (new)"
check_dir_empty ~/.thumbnails "Thumbnail cache (old)"

# Check trash
check_dir_empty ~/.local/share/Trash/files "Trash files"
check_dir_empty ~/.local/share/Trash/info "Trash info"

# Check GNOME Tracker
if [ -d ~/.cache/tracker3 ] || [ -d ~/.cache/tracker ]; then
    TRACKER_COUNT=$(find ~/.cache/tracker* -type f 2>/dev/null | wc -l)
    if [ "$TRACKER_COUNT" -eq 0 ]; then
        pass "GNOME Tracker cache cleared"
    else
        fail "GNOME Tracker cache" "Empty cache" "Found $TRACKER_COUNT files"
    fi
else
    pass "GNOME Tracker cache - Not present"
fi

if [ -d ~/.local/state/tracker ]; then
    STATE_COUNT=$(find ~/.local/state/tracker -type f 2>/dev/null | wc -l)
    if [ "$STATE_COUNT" -eq 0 ]; then
        pass "GNOME Tracker state cleared"
    else
        fail "GNOME Tracker state" "Empty state" "Found $STATE_COUNT files"
    fi
else
    pass "GNOME Tracker state - Not present"
fi

# Check Zeitgeist
if [ -d ~/.local/share/zeitgeist ]; then
    ZEIT_COUNT=$(find ~/.local/share/zeitgeist -type f 2>/dev/null | wc -l)
    if [ "$ZEIT_COUNT" -eq 0 ]; then
        pass "Zeitgeist logs cleared"
    else
        fail "Zeitgeist logs" "Empty directory" "Found $ZEIT_COUNT files"
    fi
else
    pass "Zeitgeist logs - Not present"
fi

echo ""
echo "[*] Checking NetworkManager..."

# Check NetworkManager connections
if [ -d /etc/NetworkManager/system-connections ]; then
    if ! sudo ls /etc/NetworkManager/system-connections/EvilAP >/dev/null 2>&1; then
        pass "NetworkManager EvilAP connection removed"
    else
        fail "NetworkManager connection" "EvilAP removed" "EvilAP still exists"
    fi
    
    # Check if NYX-TEST connection was removed
    if command -v nmcli >/dev/null 2>&1; then
        if ! sudo nmcli c show NYX-TEST >/dev/null 2>&1; then
            pass "NetworkManager NYX-TEST connection removed"
        else
            fail "NetworkManager NYX-TEST" "Connection removed" "Connection still exists"
        fi
    fi
fi

echo ""
echo "[*] Checking advanced artifacts..."

# Check if test image artifacts are cleaned
if [ ! -f ~/Pictures/red.png ]; then
    pass "Test image removed"
elif [ -f ~/.cache/thumbnails/*/$(echo -n "file://$(realpath ~/Pictures/red.png)" | md5sum | cut -d' ' -f1).png ]; then
    fail "Test image thumbnail" "Thumbnail removed" "Thumbnail still exists"
else
    pass "Test image thumbnail cleaned"
fi

# Verify ARP cache was flushed (difficult to verify definitively)
ARP_COUNT=$(ip neigh show 2>/dev/null | grep -v FAILED | wc -l || arp -a 2>/dev/null | wc -l || echo "0")
pass "ARP cache checked (current entries: $ARP_COUNT)"

echo ""
echo "[*] Checking extended module artifacts..."

# Package Manager Artifacts
echo ""
echo "[*] Checking package manager artifacts..."

# APT/DPKG artifacts
check_not_exists /var/cache/apt/archives/malicious-tool_1.0_amd64.deb "APT malicious tool cache"
check_not_exists /var/cache/apt/archives/nmap_7.80_amd64.deb "APT nmap cache"
check_log_no_marker /var/log/apt/history.log "netcat-openbsd" "APT history log"
check_log_no_marker /var/log/apt/term.log "hydra" "APT term log"
check_log_no_marker /var/log/dpkg.log "john" "DPKG log"

# YUM/DNF artifacts
check_not_exists /var/cache/yum/x86_64/7/base/suspicious-tool-1.0-1.x86_64.rpm "YUM suspicious tool cache"
check_not_exists /var/cache/dnf/fedora/packages/ncat-7.70-1.fc30.x86_64.rpm "DNF ncat cache"
check_log_no_marker /var/log/yum.log "nmap-7.70" "YUM log"
check_log_no_marker /var/log/dnf.log "hydra-9.0" "DNF log"

# Pacman artifacts
check_not_exists /var/cache/pacman/pkg/nmap-7.80-1-x86_64.pkg.tar.xz "Pacman nmap cache"
check_not_exists /var/cache/pacman/pkg/john-1.9.0-1-x86_64.pkg.tar.xz "Pacman john cache"
check_log_no_marker /var/log/pacman.log "installed nmap" "Pacman log"

# Container/VM Artifacts
echo ""
echo "[*] Checking container/VM artifacts..."

# Docker artifacts
check_empty /var/lib/docker/containers/abc123def456/abc123def456-json.log "Docker container log 1"
check_empty /var/lib/docker/containers/def456ghi789/def456ghi789-json.log "Docker container log 2"
check_not_exists ~/.docker/config.json "Docker user config"
check_not_exists ~/.docker/machine/machines/evil-host/config.json "Docker machine config"

# Podman/K8s artifacts
check_not_exists /var/lib/containers/storage/overlay/123abc/userdata/suspicious-mount.json "Podman overlay userdata"
check_empty /var/log/pods/kube-system_malicious-pod_abc123/container.log "K8s pod log"

# Libvirt/QEMU artifacts
check_empty /var/log/libvirt/qemu/evil-vm.log "Libvirt QEMU log"
check_not_exists /var/cache/libvirt/qemu/capabilities.xml "Libvirt cache capabilities"
check_not_exists /var/cache/libvirt/qemu/evil-vm.xml "Libvirt cache VM metadata"

# Browser Artifacts  
echo ""
echo "[*] Checking browser artifacts..."

# Firefox artifacts
check_not_exists ~/.mozilla/firefox/profile.default-release/cache2/entries/evil-site-cache "Firefox cache entry"
check_not_exists ~/.mozilla/firefox/profile.default-release/storage/default/evil-site-storage "Firefox storage data"
check_not_exists ~/.mozilla/firefox/profile.default-release/thumbnails/evil-thumbnail.jpg "Firefox thumbnail"
check_not_exists ~/.mozilla/firefox/profile.default-release/sessionstore-backups/recovery.jsonlz4 "Firefox session backup"

# Firefox SQLite databases
if command -v sqlite3 >/dev/null 2>&1; then
    if [ -f ~/.mozilla/firefox/profile.default-release/places.sqlite ]; then
        PLACES_COUNT=$(sqlite3 ~/.mozilla/firefox/profile.default-release/places.sqlite "SELECT COUNT(*) FROM moz_places WHERE url LIKE '%evil%';" 2>/dev/null || echo "0")
        if [ "$PLACES_COUNT" -eq 0 ]; then
            pass "Firefox places database cleaned"
        else
            fail "Firefox places database" "No evil URLs" "Found $PLACES_COUNT evil URLs"
        fi
    else
        pass "Firefox places database - File removed"
    fi
    
    if [ -f ~/.mozilla/firefox/profile.default-release/cookies.sqlite ]; then
        COOKIES_COUNT=$(sqlite3 ~/.mozilla/firefox/profile.default-release/cookies.sqlite "SELECT COUNT(*) FROM moz_cookies WHERE host LIKE '%evil%';" 2>/dev/null || echo "0")
        if [ "$COOKIES_COUNT" -eq 0 ]; then
            pass "Firefox cookies database cleaned"
        else
            fail "Firefox cookies database" "No evil cookies" "Found $COOKIES_COUNT evil cookies"
        fi
    else
        pass "Firefox cookies database - File removed"
    fi
else
    check_not_exists ~/.mozilla/firefox/profile.default-release/places.sqlite "Firefox places database"
    check_not_exists ~/.mozilla/firefox/profile.default-release/cookies.sqlite "Firefox cookies database"
fi

check_not_exists ~/.mozilla/firefox/profile.default-release/formhistory.sqlite "Firefox form history database"

# Chrome/Chromium artifacts
check_not_exists ~/.config/google-chrome/Default/Cache/evil-cache-entry "Chrome cache entry"
check_not_exists ~/.config/google-chrome/Default/History "Chrome history"
check_not_exists ~/.config/google-chrome/Default/Cookies "Chrome cookies"
check_not_exists ~/.config/google-chrome/Default/Web\ Data "Chrome web data"
check_not_exists ~/.config/google-chrome/Default/Top\ Sites "Chrome top sites"

check_not_exists ~/.config/chromium/Default/Cache/evil-cache-entry "Chromium cache entry"
check_not_exists ~/.config/chromium/Default/History "Chromium history"
check_not_exists ~/.config/chromium/Default/Cookies "Chromium cookies"
check_not_exists ~/.config/chromium/Default/Web\ Data "Chromium web data"
check_not_exists ~/.config/chromium/Default/Top\ Sites "Chromium top sites"

# SSH Artifacts
echo ""
echo "[*] Checking SSH artifacts..."

# SSH user artifacts
check_empty ~/.ssh/known_hosts "SSH known_hosts"
check_not_exists ~/.ssh/connection.log "SSH connection log"
check_not_exists ~/.ssh/debug.log "SSH debug log"

# System SSH logs - check that SSH entries were removed
for log in /var/log/auth.log /var/log/secure; do
    if [ -f "$log" ]; then
        SSH_COUNT=$(sudo grep -c "sshd\[" "$log" 2>/dev/null | head -1 || echo "0")
        # Ensure SSH_COUNT is a clean integer
        SSH_COUNT=$(echo "$SSH_COUNT" | tr -d '\n' | grep -o '[0-9]*' | head -1)
        [ -z "$SSH_COUNT" ] && SSH_COUNT=0
        
        if [ "$SSH_COUNT" -eq 0 ]; then
            pass "SSH entries removed from $(basename "$log")"
        else
            fail "SSH entries in $(basename "$log")" "No SSH entries" "Found $SSH_COUNT SSH entries"
        fi
    else
        pass "SSH log $(basename "$log") - File removed"
    fi
done

# Additional Systemd Artifacts
echo ""
echo "[*] Checking additional systemd artifacts..."

check_not_exists /var/lib/systemd/random-seed "systemd random seed"
check_not_exists /run/log/journal/abc123def456/system.journal "systemd live session journal"
check_not_exists /run/log/journal/abc123def456/user-1000.journal "systemd live session user journal"

# Print Subsystem Artifacts
echo ""
echo "[*] Checking print subsystem artifacts..."

# CUPS artifacts
check_not_exists /var/spool/cups/c00001 "CUPS print job 1"
check_not_exists /var/spool/cups/c00002 "CUPS print job 2"
check_not_exists /var/spool/cups/c00003 "CUPS print job 3"

check_empty /var/log/cups/access_log "CUPS access log"
check_empty /var/log/cups/error_log "CUPS error log"
check_empty /var/log/cups/page_log "CUPS page log"

# Additional Forensic Artifacts
echo ""
echo "[*] Checking additional forensic artifacts..."

# DHCP leases
check_not_exists /var/lib/dhclient/dhclient.eth0.leases "DHCP leases"

# GTK bookmarks
check_empty ~/.config/gtk-3.0/bookmarks "GTK bookmarks"

# Recently used files
if [ -f ~/.local/share/recently-used.xbel ]; then
    RECENT_COUNT=$(grep -c "suspicious\|payload\|malware" ~/.local/share/recently-used.xbel 2>/dev/null | head -1 || echo "0")
    # Ensure RECENT_COUNT is a clean integer
    RECENT_COUNT=$(echo "$RECENT_COUNT" | tr -d '\n' | grep -o '[0-9]*' | head -1)
    [ -z "$RECENT_COUNT" ] && RECENT_COUNT=0
    
    if [ "$RECENT_COUNT" -eq 0 ]; then
        pass "Recently used files cleaned"
    else
        fail "Recently used files" "No suspicious entries" "Found $RECENT_COUNT suspicious entries"
    fi
else
    pass "Recently used files - File removed"
fi

# Crash dumps
check_not_exists /var/crash/core.suspicious-binary.12345.gz "Crash dump"
check_not_exists /var/crash/_usr_bin_evil-tool.12345.crash "Crash report"

# VS Code/Editor traces
check_not_exists ~/.local/share/code-server/User/settings.json "VS Code server settings"
check_not_exists ~/.config/Code/User/settings.json "VS Code user settings"

# JetBrains traces
check_empty ~/.local/share/.IntelliJIdea2023.1/system/log/idea.log "JetBrains IDE log"

# Extended Verification Summary
echo ""
echo "[*] Extended verification complete..."

# Count additional extended artifacts that should be cleaned
EXTENDED_ARTIFACTS=0

# Package manager artifacts
[ -f /var/cache/apt/archives/malicious-tool_1.0_amd64.deb ] && EXTENDED_ARTIFACTS=$((EXTENDED_ARTIFACTS + 1))
[ -f /var/cache/yum/x86_64/7/base/suspicious-tool-1.0-1.x86_64.rpm ] && EXTENDED_ARTIFACTS=$((EXTENDED_ARTIFACTS + 1))
[ -f /var/cache/pacman/pkg/nmap-7.80-1-x86_64.pkg.tar.xz ] && EXTENDED_ARTIFACTS=$((EXTENDED_ARTIFACTS + 1))

# Container artifacts
[ -s /var/lib/docker/containers/abc123def456/abc123def456-json.log ] && EXTENDED_ARTIFACTS=$((EXTENDED_ARTIFACTS + 1))
[ -f ~/.docker/config.json ] && EXTENDED_ARTIFACTS=$((EXTENDED_ARTIFACTS + 1))

# Browser artifacts
[ -f ~/.mozilla/firefox/profile.default-release/places.sqlite ] && EXTENDED_ARTIFACTS=$((EXTENDED_ARTIFACTS + 1))
[ -f ~/.config/google-chrome/Default/History ] && EXTENDED_ARTIFACTS=$((EXTENDED_ARTIFACTS + 1))

# SSH artifacts  
[ -s ~/.ssh/known_hosts ] && EXTENDED_ARTIFACTS=$((EXTENDED_ARTIFACTS + 1))

# Print artifacts
[ -f /var/spool/cups/c00001 ] && EXTENDED_ARTIFACTS=$((EXTENDED_ARTIFACTS + 1))

if [ "$EXTENDED_ARTIFACTS" -eq 0 ]; then
    pass "Extended modules verification - All artifacts cleaned"
else
    fail "Extended modules verification" "All extended artifacts cleaned" "$EXTENDED_ARTIFACTS extended artifacts remain"
fi

# Final summary
echo ""
echo "================================"
echo "Verification Complete"
echo "================================"
echo ""
echo -e "${GREEN}Passed checks: $PASSED_CHECKS${NC}"

if [ $FAILED_CHECKS -gt 0 ]; then
    echo -e "${RED}Failed checks: $FAILED_CHECKS${NC}"
    echo ""
    echo -e "${RED}VERIFICATION FAILED!${NC}"
    echo "Some artifacts were not properly cleaned."
    exit 1
else
    echo ""
    echo -e "${GREEN}ALL CHECKS PASSED!${NC}"
    echo "All artifacts were successfully cleaned."
    exit 0
fi
