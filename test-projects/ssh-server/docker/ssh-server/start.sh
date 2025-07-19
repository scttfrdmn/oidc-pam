#!/bin/bash

set -e

echo "Starting OIDC PAM SSH Server Test Container..."

# Set up environment
export PATH="/usr/local/bin:$PATH"

# Create necessary directories
mkdir -p /var/run/sshd
mkdir -p /var/log/ssh-server
mkdir -p /var/log/oidc-auth

# Set permissions
chown -R syslog:adm /var/log/ssh-server
chown -R oidc-auth:oidc-auth /var/log/oidc-auth
chmod 755 /var/log/ssh-server
chmod 755 /var/log/oidc-auth

# Generate SSH host keys if they don't exist
if [ ! -f /etc/ssh/host-keys/ssh_host_rsa_key ]; then
    echo "Generating SSH host keys..."
    ssh-keygen -t rsa -f /etc/ssh/host-keys/ssh_host_rsa_key -N '' -C "test-ssh-server"
    ssh-keygen -t ecdsa -f /etc/ssh/host-keys/ssh_host_ecdsa_key -N '' -C "test-ssh-server"
    ssh-keygen -t ed25519 -f /etc/ssh/host-keys/ssh_host_ed25519_key -N '' -C "test-ssh-server"
fi

# Copy host keys to SSH directory
cp /etc/ssh/host-keys/* /etc/ssh/

# Set SSH host key permissions
chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub

# Wait for OIDC broker to be available
echo "Waiting for OIDC broker..."
while ! curl -sf "$OIDC_BROKER_URL/health" > /dev/null 2>&1; do
    echo "OIDC broker not ready, waiting..."
    sleep 5
done
echo "OIDC broker is ready!"

# Update OIDC configuration if needed
if [ ! -f /etc/oidc-auth/broker.yaml ]; then
    echo "Creating default OIDC broker configuration..."
    cat > /etc/oidc-auth/broker.yaml << EOF
oidc:
  providers:
    - name: "test-keycloak"
      issuer: "http://keycloak:8080/realms/test-realm"
      client_id: "oidc-pam-client"
      client_secret: "test-secret"
      scopes: ["openid", "email", "profile", "groups"]
      device_flow_enabled: true

authentication:
  policies:
    default:
      require_groups: ["users", "ssh-users"]
      session_duration: "8h"
      audit_level: "standard"
    
    ssh_operations:
      require_groups: ["ssh-users"]
      session_duration: "4h"
      audit_level: "detailed"

logging:
  level: "$OIDC_LOG_LEVEL"
  format: "json"
  output: "/var/log/oidc-auth/broker.log"
  audit_enabled: true
  audit_level: "detailed"
  audit_file: "/var/log/oidc-auth/audit.log"

network:
  bind_address: "0.0.0.0"
  port: 8080

security:
  encryption_key: "test-key-for-ssh-server-testing"
  token_cache_duration: "1h"
EOF
fi

# Set OIDC configuration permissions
chown oidc-auth:oidc-auth /etc/oidc-auth/broker.yaml
chmod 640 /etc/oidc-auth/broker.yaml

# Configure rsyslog for SSH logging
echo "Configuring logging..."
cat > /etc/rsyslog.d/50-ssh-server.conf << EOF
# SSH server logging
:programname, isequal, "sshd" /var/log/ssh-server/auth.log
& stop

# OIDC authentication logging
:programname, isequal, "oidc-auth" /var/log/ssh-server/oidc.log
& stop

# PAM logging
:programname, isequal, "pam_oidc" /var/log/ssh-server/pam.log
& stop
EOF

# Start rsyslog
echo "Starting rsyslog..."
service rsyslog start

# Configure logrotate
echo "Configuring log rotation..."
cat > /etc/logrotate.d/ssh-server << EOF
/var/log/ssh-server/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 syslog adm
    postrotate
        systemctl reload rsyslog
    endscript
}
EOF

# Set debug mode if enabled
if [ "$ENABLE_DEBUG" = "true" ]; then
    echo "Debug mode enabled"
    export SSH_LOG_LEVEL="debug"
    export OIDC_LOG_LEVEL="debug"
    
    # Enable debug logging in SSH
    sed -i 's/#LogLevel INFO/LogLevel DEBUG/' /etc/ssh/sshd_config
fi

# Test SSH configuration
echo "Testing SSH configuration..."
if ! sshd -t; then
    echo "SSH configuration test failed!"
    exit 1
fi

# Print system information
echo "System information:"
echo "- Container: $(hostname)"
echo "- SSH log level: $SSH_LOG_LEVEL"
echo "- OIDC log level: $OIDC_LOG_LEVEL"
echo "- OIDC broker URL: $OIDC_BROKER_URL"
echo "- Debug mode: $ENABLE_DEBUG"

# Print user information
echo "Test users:"
echo "- testuser (oidc-users, ssh-users)"
echo "- admin (oidc-admin, oidc-users, ssh-users)"
echo "- developer (oidc-developers, oidc-users, ssh-users)"
echo "- contractor (oidc-contractors, ssh-users)"
echo "- service (oidc-service)"

# Start SSH server
echo "Starting SSH server..."
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config