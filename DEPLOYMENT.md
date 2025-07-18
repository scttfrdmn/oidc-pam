# OIDC PAM Authentication - Deployment Guide

This guide provides comprehensive instructions for deploying the OIDC PAM authentication system in production environments.

## ⚠️ Production Deployment Warning

This is an alpha release. Thoroughly test all components in a non-production environment before deploying to production. Always maintain emergency access methods.

## Architecture Overview

The OIDC PAM authentication system consists of:

1. **OIDC Auth Broker**: Core authentication service
2. **PAM Module**: System integration for authentication
3. **OIDC Provider**: External identity provider (Keycloak, Auth0, etc.)
4. **Supporting Infrastructure**: Logging, monitoring, backup systems

## Prerequisites

### System Requirements

#### Minimum Requirements
- Linux server with PAM support
- 2 CPU cores
- 4 GB RAM
- 20 GB storage
- Network connectivity to OIDC provider

#### Recommended Requirements
- 4+ CPU cores
- 8+ GB RAM
- 50+ GB SSD storage
- High-availability network connection
- Load balancer for multiple instances

#### Supported Operating Systems
- Ubuntu 20.04 LTS or later
- CentOS 8 or later
- RHEL 8 or later
- Debian 11 or later
- Amazon Linux 2
- SUSE Linux Enterprise Server 15+

### Network Requirements

#### Firewall Rules
```bash
# Inbound rules
22/tcp    # SSH access
80/tcp    # HTTP (redirect to HTTPS)
443/tcp   # HTTPS
8080/tcp  # OIDC Broker (internal)

# Outbound rules
443/tcp   # HTTPS to OIDC provider
53/tcp    # DNS queries
53/udp    # DNS queries
123/udp   # NTP synchronization
```

#### DNS Requirements
- Resolvable FQDN for the server
- DNS resolution to OIDC provider
- NTP synchronization configured

## Installation Methods

### Method 1: Package Installation (Recommended)

#### Debian/Ubuntu (.deb packages)
```bash
# Download and install package
wget https://github.com/yourusername/oidc-pam/releases/latest/download/oidc-pam_1.0.0-alpha_amd64.deb
sudo dpkg -i oidc-pam_1.0.0-alpha_amd64.deb
sudo apt-get install -f  # Fix dependencies if needed
```

#### RHEL/CentOS (.rpm packages)
```bash
# Download and install package
wget https://github.com/yourusername/oidc-pam/releases/latest/download/oidc-pam-1.0.0-alpha.x86_64.rpm
sudo rpm -ivh oidc-pam-1.0.0-alpha.x86_64.rpm
```

### Method 2: Binary Installation

```bash
# Download binary distribution
wget https://github.com/yourusername/oidc-pam/releases/latest/download/oidc-pam-linux-amd64.tar.gz
tar -xzf oidc-pam-linux-amd64.tar.gz
cd oidc-pam-linux-amd64

# Run installation script
sudo ./install.sh

# Verify installation
systemctl status oidc-auth-broker
```

### Method 3: Source Compilation

```bash
# Install build dependencies
sudo apt-get update
sudo apt-get install -y golang-go git make gcc libc6-dev libpam0g-dev

# Clone and build
git clone https://github.com/yourusername/oidc-pam.git
cd oidc-pam
make build
sudo make install
```

## Configuration

### 1. OIDC Provider Setup

#### Keycloak Configuration
```bash
# Create client in Keycloak admin console
Client ID: oidc-pam-production
Client Protocol: openid-connect
Access Type: confidential
Valid Redirect URIs: http://localhost:8080/callback
Web Origins: *

# Enable device flow
Advanced Settings > OAuth 2.0 Device Authorization Grant Enabled: ON

# Configure mappers for SSH keys and groups
```

#### Auth0 Configuration
```bash
# Create Regular Web Application
Name: OIDC PAM Production
Domain: your-domain.auth0.com
Client ID: [generated]
Client Secret: [generated]

# Enable device flow in Advanced Settings
Grant Types: Device Code
```

### 2. Broker Configuration

Create `/etc/oidc-auth/broker.yaml`:

```yaml
# Production OIDC Broker Configuration
oidc:
  providers:
    - name: "production"
      issuer: "https://your-oidc-provider.com"
      client_id: "your-production-client-id"
      client_secret: "your-production-client-secret"
      scopes: ["openid", "email", "profile", "groups"]
      device_flow_enabled: true
      discovery_cache_duration: "1h"
      
  # Connection settings
  timeout: "30s"
  retry_count: 3
  retry_delay: "5s"

# Authentication policies
authentication:
  policies:
    default:
      require_groups: ["employees", "contractors"]
      session_duration: "8h"
      max_concurrent_sessions: 3
      require_mfa: false
      audit_level: "standard"
      
    admin_operations:
      require_groups: ["administrators", "sysadmins"]
      session_duration: "4h"
      max_concurrent_sessions: 1
      require_mfa: true
      audit_level: "detailed"
      
    sudo_operations:
      require_groups: ["sudo-users", "administrators"]
      session_duration: "1h"
      max_concurrent_sessions: 2
      require_mfa: true
      audit_level: "detailed"

# Security settings
security:
  encryption_key: "your-32-character-encryption-key-here"
  token_cache_duration: "1h"
  max_token_age: "24h"
  secure_cookies: true
  csrf_protection: true
  
# Network settings
network:
  bind_address: "127.0.0.1"
  port: 8080
  tls_enabled: false  # Use reverse proxy for TLS
  cors_enabled: false
  
# Logging configuration
logging:
  level: "info"
  format: "json"
  output: "/var/log/oidc-auth/broker.log"
  max_size: "100MB"
  max_backups: 10
  max_age: 30
  
  # Audit logging
  audit_enabled: true
  audit_level: "standard"
  audit_file: "/var/log/oidc-auth/audit.log"
  audit_max_size: "500MB"
  audit_max_backups: 20
  audit_max_age: 90

# Monitoring settings
monitoring:
  enabled: true
  metrics_port: 9090
  health_check_enabled: true
  health_check_path: "/health"
  ready_check_path: "/ready"
```

### 3. PAM Configuration

#### SSH Configuration (`/etc/pam.d/ssh`)
```bash
# Production SSH PAM configuration
auth    sufficient  pam_oidc.so config=/etc/oidc-auth/broker.yaml service=ssh
auth    requisite   pam_deny.so
auth    required    pam_unix.so try_first_pass

account sufficient  pam_oidc.so config=/etc/oidc-auth/broker.yaml
account required    pam_unix.so
account required    pam_access.so

session required    pam_unix.so
session optional    pam_oidc.so config=/etc/oidc-auth/broker.yaml
session required    pam_systemd.so
session optional    pam_env.so
```

#### Sudo Configuration (`/etc/pam.d/sudo`)
```bash
# Production sudo PAM configuration
auth    sufficient  pam_oidc.so config=/etc/oidc-auth/broker.yaml operation=sudo target_user=%u
auth    requisite   pam_deny.so
auth    required    pam_unix.so try_first_pass

account sufficient  pam_oidc.so config=/etc/oidc-auth/broker.yaml
account required    pam_unix.so
account required    pam_access.so
account required    pam_time.so

session required    pam_unix.so
session optional    pam_oidc.so config=/etc/oidc-auth/broker.yaml
session optional    pam_systemd.so
```

### 4. System Service Configuration

#### Systemd Service (`/etc/systemd/system/oidc-auth-broker.service`)
```ini
[Unit]
Description=OIDC Authentication Broker
After=network.target
Wants=network.target

[Service]
Type=simple
User=oidc-auth
Group=oidc-auth
ExecStart=/usr/bin/oidc-auth-broker --config /etc/oidc-auth/broker.yaml
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/oidc-auth /var/lib/oidc-auth

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Environment
Environment=GOMAXPROCS=2
Environment=GOGC=100

[Install]
WantedBy=multi-user.target
```

## Security Hardening

### 1. File Permissions

```bash
# Set secure permissions
sudo chown -R oidc-auth:oidc-auth /etc/oidc-auth
sudo chmod 750 /etc/oidc-auth
sudo chmod 640 /etc/oidc-auth/broker.yaml

# Log directory permissions
sudo chown -R oidc-auth:oidc-auth /var/log/oidc-auth
sudo chmod 750 /var/log/oidc-auth

# PAM module permissions
sudo chown root:root /lib/security/pam_oidc.so
sudo chmod 644 /lib/security/pam_oidc.so
```

### 2. Network Security

#### Firewall Configuration (UFW)
```bash
# Reset firewall
sudo ufw --force reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow OIDC broker (internal only)
sudo ufw allow from 127.0.0.1 to any port 8080

# Enable firewall
sudo ufw enable
```

#### Firewall Configuration (iptables)
```bash
# Save current rules
sudo iptables-save > /tmp/iptables.backup

# Flush existing rules
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X

# Default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback
sudo iptables -I INPUT -i lo -j ACCEPT
sudo iptables -I OUTPUT -o lo -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

### 3. SSL/TLS Configuration

#### Generate SSL Certificates
```bash
# Option 1: Let's Encrypt
sudo apt-get install certbot
sudo certbot certonly --standalone -d your-domain.com

# Option 2: Self-signed (testing only)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/oidc-pam.key \
  -out /etc/ssl/certs/oidc-pam.crt
```

#### Nginx Reverse Proxy
```nginx
# /etc/nginx/sites-available/oidc-pam
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
    
    location /health {
        proxy_pass http://127.0.0.1:8080;
        access_log off;
    }
}
```

## Monitoring and Logging

### 1. Log Configuration

#### Rsyslog Configuration
```bash
# /etc/rsyslog.d/50-oidc-auth.conf
# OIDC Auth logging
:programname, isequal, "oidc-auth-broker" /var/log/oidc-auth/broker.log
& stop

# Audit logging
:programname, isequal, "oidc-auth-audit" /var/log/oidc-auth/audit.log
& stop
```

#### Logrotate Configuration
```bash
# /etc/logrotate.d/oidc-auth
/var/log/oidc-auth/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 oidc-auth oidc-auth
    postrotate
        systemctl reload oidc-auth-broker
    endscript
}
```

### 2. Monitoring Setup

#### Prometheus Configuration
```yaml
# /etc/prometheus/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'oidc-auth-broker'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
    scrape_interval: 5s
```

#### Grafana Dashboard
```json
{
  "dashboard": {
    "title": "OIDC PAM Authentication",
    "panels": [
      {
        "title": "Authentication Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(oidc_auth_requests_total[5m])",
            "legendFormat": "Requests/sec"
          }
        ]
      },
      {
        "title": "Success Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "rate(oidc_auth_success_total[5m]) / rate(oidc_auth_requests_total[5m]) * 100",
            "legendFormat": "Success %"
          }
        ]
      }
    ]
  }
}
```

## High Availability Setup

### 1. Load Balancer Configuration

#### HAProxy Configuration
```bash
# /etc/haproxy/haproxy.cfg
global
    daemon
    log 127.0.0.1:514 local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog
    option dontlognull

frontend oidc_auth_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/oidc-pam.pem
    redirect scheme https if !{ ssl_fc }
    default_backend oidc_auth_backend

backend oidc_auth_backend
    balance roundrobin
    option httpchk GET /health
    server oidc-auth-1 192.168.1.10:8080 check
    server oidc-auth-2 192.168.1.11:8080 check
    server oidc-auth-3 192.168.1.12:8080 check
```

### 2. Database Backend (Optional)

#### PostgreSQL Configuration
```sql
-- Create database and user
CREATE DATABASE oidc_auth;
CREATE USER oidc_auth WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE oidc_auth TO oidc_auth;

-- Create tables for session storage
CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

## Backup and Recovery

### 1. Backup Strategy

#### Configuration Backup
```bash
#!/bin/bash
# /usr/local/bin/backup-oidc-config.sh

BACKUP_DIR="/backup/oidc-auth"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/config-backup-$DATE.tar.gz"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup configuration
tar -czf $BACKUP_FILE \
    /etc/oidc-auth/ \
    /etc/pam.d/ \
    /etc/systemd/system/oidc-auth-broker.service

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "config-backup-*.tar.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
```

#### Log Backup
```bash
#!/bin/bash
# /usr/local/bin/backup-oidc-logs.sh

BACKUP_DIR="/backup/oidc-auth/logs"
DATE=$(date +%Y%m%d)
BACKUP_FILE="$BACKUP_DIR/logs-backup-$DATE.tar.gz"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup logs
tar -czf $BACKUP_FILE /var/log/oidc-auth/

# Cleanup old backups (keep 90 days)
find $BACKUP_DIR -name "logs-backup-*.tar.gz" -mtime +90 -delete

echo "Log backup completed: $BACKUP_FILE"
```

### 2. Recovery Procedures

#### Configuration Recovery
```bash
#!/bin/bash
# /usr/local/bin/restore-oidc-config.sh

if [ -z "$1" ]; then
    echo "Usage: $0 <backup-file>"
    exit 1
fi

BACKUP_FILE="$1"

# Stop service
systemctl stop oidc-auth-broker

# Restore configuration
tar -xzf $BACKUP_FILE -C /

# Reload systemd
systemctl daemon-reload

# Start service
systemctl start oidc-auth-broker

# Verify service
systemctl status oidc-auth-broker

echo "Configuration restored from: $BACKUP_FILE"
```

## Maintenance

### 1. Regular Maintenance Tasks

#### Weekly Tasks
```bash
# Check service status
systemctl status oidc-auth-broker

# Check logs for errors
journalctl -u oidc-auth-broker --since "1 week ago" | grep -i error

# Check disk usage
du -sh /var/log/oidc-auth/

# Test authentication
./test-broker
```

#### Monthly Tasks
```bash
# Update system packages
sudo apt-get update && sudo apt-get upgrade

# Rotate logs manually if needed
sudo logrotate -f /etc/logrotate.d/oidc-auth

# Check SSL certificate expiration
openssl x509 -in /etc/ssl/certs/oidc-pam.crt -text -noout | grep "Not After"

# Review audit logs
sudo grep -i "failed\|error\|denied" /var/log/oidc-auth/audit.log
```

### 2. Performance Tuning

#### System Tuning
```bash
# /etc/sysctl.d/99-oidc-auth.conf
# Network tuning
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 8192 16777216
net.ipv4.tcp_wmem = 4096 8192 16777216

# Connection limits
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.ip_local_port_range = 15000 65000

# Apply settings
sudo sysctl -p /etc/sysctl.d/99-oidc-auth.conf
```

#### Service Limits
```bash
# /etc/systemd/system/oidc-auth-broker.service.d/limits.conf
[Service]
LimitNOFILE=65536
LimitNPROC=4096
LimitMEMLOCK=64M
```

## Troubleshooting

### Common Issues

#### 1. Service Won't Start
```bash
# Check service status
systemctl status oidc-auth-broker

# Check logs
journalctl -u oidc-auth-broker -f

# Validate configuration
oidc-auth-broker --config /etc/oidc-auth/broker.yaml --validate

# Check file permissions
ls -la /etc/oidc-auth/
```

#### 2. Authentication Failures
```bash
# Check OIDC provider connectivity
curl -v https://your-oidc-provider.com/.well-known/openid-configuration

# Check broker logs
sudo tail -f /var/log/oidc-auth/broker.log

# Check PAM logs
sudo tail -f /var/log/auth.log

# Enable debug mode
# Edit /etc/oidc-auth/broker.yaml
logging:
  level: "debug"
```

#### 3. Performance Issues
```bash
# Check system resources
top
htop
free -h
df -h

# Check network connectivity
ping your-oidc-provider.com
traceroute your-oidc-provider.com

# Monitor connections
netstat -an | grep :8080
ss -tuln | grep :8080
```

## Security Considerations

### 1. Security Checklist

- [ ] SSL/TLS certificates properly configured
- [ ] Firewall rules implemented
- [ ] File permissions secured
- [ ] Audit logging enabled
- [ ] Backup procedures tested
- [ ] Emergency access methods available
- [ ] Regular security updates applied
- [ ] Monitoring and alerting configured

### 2. Security Monitoring

#### Failed Authentication Alerts
```bash
#!/bin/bash
# /usr/local/bin/monitor-auth-failures.sh

THRESHOLD=10
TIMEFRAME="5 minutes"

# Count failed authentication attempts
FAILURES=$(journalctl -u oidc-auth-broker --since "$TIMEFRAME ago" | grep -c "authentication failed")

if [ $FAILURES -gt $THRESHOLD ]; then
    echo "ALERT: $FAILURES authentication failures in the last $TIMEFRAME"
    # Send alert (email, Slack, etc.)
fi
```

### 3. Compliance

#### Audit Log Review
```bash
#!/bin/bash
# /usr/local/bin/audit-review.sh

# Generate daily audit report
DATE=$(date +%Y-%m-%d)
REPORT_FILE="/var/log/oidc-auth/audit-report-$DATE.txt"

echo "OIDC Authentication Audit Report - $DATE" > $REPORT_FILE
echo "=============================================" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Authentication statistics
echo "Authentication Statistics:" >> $REPORT_FILE
grep "authentication" /var/log/oidc-auth/audit.log | \
    grep "$DATE" | \
    awk '{print $5}' | \
    sort | uniq -c >> $REPORT_FILE

# Failed attempts
echo "" >> $REPORT_FILE
echo "Failed Authentication Attempts:" >> $REPORT_FILE
grep "failed" /var/log/oidc-auth/audit.log | \
    grep "$DATE" >> $REPORT_FILE

# Privilege escalation
echo "" >> $REPORT_FILE
echo "Privilege Escalation Events:" >> $REPORT_FILE
grep "sudo\|su" /var/log/oidc-auth/audit.log | \
    grep "$DATE" >> $REPORT_FILE

echo "Audit report generated: $REPORT_FILE"
```

## Support and Maintenance

### 1. Support Contacts

- **System Administrator**: admin@yourcompany.com
- **Security Team**: security@yourcompany.com
- **On-call Engineer**: oncall@yourcompany.com

### 2. Escalation Procedures

#### Level 1: Service Issues
- Check service status
- Review logs
- Restart service if needed
- Test authentication

#### Level 2: Security Issues
- Isolate affected systems
- Preserve logs and evidence
- Contact security team
- Implement containment measures

#### Level 3: Emergency Response
- Activate emergency access
- Contact on-call engineer
- Implement disaster recovery
- Document incident

---

This deployment guide provides comprehensive instructions for production deployment of the OIDC PAM authentication system. Always test thoroughly in a non-production environment before deploying to production.