FROM ubuntu:22.04

# Set timezone non-interactively to avoid prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install necessary packages
RUN apt-get update && apt-get install -y \
    sudo \
    curl \
    wget \
    vim \
    nano \
    bash \
    zsh \
    fish \
    python3 \
    mysql-client \
    postgresql-client \
    sqlite3 \
    redis-tools \
    auditd \
    systemd \
    systemd-sysv \
    procps \
    net-tools \
    iputils-ping \
    apache2 \
    nginx \
    imagemagick \
    tracker \
    zeitgeist-core \
    network-manager \
    xdg-utils \
    netcat \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create test user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:password" | chpasswd && \
    usermod -aG sudo testuser && \
    echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Copy scripts
COPY nyx.sh /usr/local/bin/nyx.sh
COPY tests/create-artifacts.sh /usr/local/bin/
COPY tests/verify-cleanup.sh /usr/local/bin/
COPY tests/entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

# Create directories for logs
RUN mkdir -p /var/log/audit && \
    touch /var/log/audit/audit.log && \
    systemctl enable auditd || true

# Switch to test user home
WORKDIR /home/testuser

# Create initial history files as testuser
USER testuser
RUN touch ~/.bash_history ~/.zsh_history ~/.python_history ~/.mysql_history ~/.sqlite_history ~/.viminfo ~/.lesshst ~/.wget-hsts

USER root

# Entry point - run tests automatically
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
