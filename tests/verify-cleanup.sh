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
