# OIDC PAM SSH Server Test Container
FROM ubuntu:22.04

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    libpam-modules \
    libpam-runtime \
    curl \
    wget \
    netcat \
    supervisor \
    rsyslog \
    logrotate \
    vim \
    less \
    htop \
    net-tools \
    iproute2 \
    ca-certificates \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /var/run/sshd \
    /var/log/ssh-server \
    /var/log/oidc-auth \
    /etc/oidc-auth \
    /etc/ssh/host-keys

# Create OIDC auth user and group
RUN groupadd -r oidc-auth && \
    useradd -r -g oidc-auth -s /bin/false oidc-auth

# Create test users
RUN useradd -m -s /bin/bash testuser && \
    useradd -m -s /bin/bash admin && \
    useradd -m -s /bin/bash developer && \
    useradd -m -s /bin/bash contractor && \
    useradd -m -s /bin/bash service && \
    echo "testuser:password123" | chpasswd && \
    echo "admin:password123" | chpasswd && \
    echo "developer:password123" | chpasswd && \
    echo "contractor:password123" | chpasswd && \
    echo "service:password123" | chpasswd

# Add users to groups
RUN usermod -aG sudo admin && \
    usermod -aG sudo developer

# Create group mappings for OIDC
RUN groupadd oidc-users && \
    groupadd oidc-admin && \
    groupadd oidc-developers && \
    groupadd oidc-contractors && \
    groupadd oidc-service && \
    groupadd ssh-users && \
    usermod -aG oidc-users,ssh-users testuser && \
    usermod -aG oidc-admin,oidc-users,ssh-users admin && \
    usermod -aG oidc-developers,oidc-users,ssh-users developer && \
    usermod -aG oidc-contractors,ssh-users contractor && \
    usermod -aG oidc-service service

# Copy PAM OIDC module (placeholder - will be mounted from host)
COPY docker/ssh-server/pam_oidc.so /lib/security/pam_oidc.so
RUN chmod 644 /lib/security/pam_oidc.so

# Copy SSH server configuration
COPY docker/ssh-server/sshd_config /etc/ssh/sshd_config
RUN chmod 644 /etc/ssh/sshd_config

# Copy PAM configurations
COPY docker/ssh-server/pam.d/ /etc/pam.d/
RUN chmod 644 /etc/pam.d/*

# Copy security configurations
COPY docker/ssh-server/security/ /etc/security/
RUN chmod 644 /etc/security/*

# Copy supervisor configuration
COPY docker/ssh-server/supervisord.conf /etc/supervisor/supervisord.conf
RUN chmod 644 /etc/supervisor/supervisord.conf

# Copy startup script
COPY docker/ssh-server/start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

# Copy test utilities
COPY docker/ssh-server/test-utils/ /usr/local/bin/
RUN chmod +x /usr/local/bin/test-*

# Copy rsyslog configuration
COPY docker/ssh-server/rsyslog.conf /etc/rsyslog.conf
RUN chmod 644 /etc/rsyslog.conf

# Copy logrotate configuration
COPY docker/ssh-server/logrotate.d/ /etc/logrotate.d/
RUN chmod 644 /etc/logrotate.d/*

# Generate SSH host keys
RUN ssh-keygen -A

# Set up SSH directory permissions
RUN chmod 700 /var/run/sshd

# Set up log directory permissions
RUN chown -R syslog:adm /var/log/ssh-server && \
    chmod 755 /var/log/ssh-server

# Set up OIDC auth directory permissions
RUN chown -R oidc-auth:oidc-auth /etc/oidc-auth && \
    chmod 750 /etc/oidc-auth

# Create symbolic links for logging
RUN ln -sf /var/log/ssh-server/auth.log /var/log/auth.log && \
    ln -sf /var/log/ssh-server/syslog /var/log/syslog

# Health check script
COPY docker/ssh-server/health-check.sh /usr/local/bin/health-check.sh
RUN chmod +x /usr/local/bin/health-check.sh

# Expose SSH port
EXPOSE 22

# Set environment variables
ENV SSH_LOG_LEVEL=info
ENV OIDC_LOG_LEVEL=info
ENV OIDC_BROKER_URL=http://oidc-broker:8080
ENV ENABLE_DEBUG=false

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /usr/local/bin/health-check.sh

# Volume mount points
VOLUME ["/var/log/ssh-server", "/etc/oidc-auth", "/etc/ssh/host-keys"]

# Start supervisor
CMD ["/usr/local/bin/start.sh"]