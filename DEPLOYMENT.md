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

## Integration Model & Scope

Understand the following before integrating oidc-pam, especially in automated
deployments:

- **PAM-only.** oidc-pam integrates exclusively through PAM. There is **no NSS
  module** (no `libnss_oidc.so`) — oidc-pam does not provide UID/username
  resolution through `nsswitch.conf`. UID/GID resolution must come from your
  existing name service (local `/etc/passwd`, SSSD, LDAP, directory sync, etc.).

- **Local accounts must already exist.** oidc-pam authenticates and provisions
  SSH keys for an account that is already present on the system; it does **not**
  create local users. Provision accounts separately (directory sync, `useradd`,
  SSSD, cloud-init, configuration management, etc.) before or alongside
  authentication.

- **Username flows *in*, not out.** PAM supplies the requested local username
  (from SSH, the console, or a front-end such as Apache/Open OnDemand). The
  broker then authenticates that identity via the OIDC device flow and uses the
  provider's `username_claim` to verify the authenticated OIDC identity is
  allowed to log in as that local user. oidc-pam does **not** resolve an OIDC
  identity into a local username, so there is no "user map" command. Front-ends
  that expect an OIDC→username mapping helper (for example Open OnDemand's
  `user_map_cmd`) should perform that mapping in their own layer; do not point
  it at an oidc-pam binary.

- **Shipped binaries.** A release provides exactly four artifacts:
  `oidc-auth-broker`, `oidc-pam-helper`, `oidc-admin`, and `pam_oidc.so`. There
  is no standalone `oidc-pam` binary.

### Identity vs. Authentication: where oidc-pam fits

oidc-pam is an **authentication** layer, not an **identity** (name service)
layer. These are two distinct responsibilities, and on most deployments they
are owned by two different components:

| Concern | Question it answers | Owned by |
|---------|---------------------|----------|
| **Identity / NSS** | Does user `alice` exist? What UID/GID/home/shell/groups? | Your name service: local `/etc/passwd`, **SSSD**, LDAP/AD, directory sync |
| **Authentication / PAM** | Can the person logging in as `alice` *prove* they are allowed to? | **oidc-pam** (OIDC device flow + SSH-key provisioning + audit) |

The recommended architecture is to **let SSSD (or your existing directory) own
identity, and let oidc-pam own authentication.** Each tool stays in its lane:

- SSSD + an LDAP/AD/AWS Identity Store backend provides NSS (so `getpwnam`,
  `id`, `ls -l`, `sudo`, file ownership, and quotas all work) and — critically
  for clusters — **consistent UIDs/GIDs across every node**, which shared
  filesystems (NFS/Lustre/EFS) require to avoid silent ownership corruption.
- oidc-pam provides the modern login experience (passkey/device-flow auth,
  automatic SSH key lifecycle, MFA/risk policy, audit trails) on top of those
  already-resolved accounts.

If you already have an identity provider for OIDC (Entra ID, Okta, AWS IAM
Identity Center, Keycloak), you almost always also have a directory backend
SSSD can consume for POSIX attributes. Use it for identity; point oidc-pam at
the same IdP for authentication.

#### Why oidc-pam does not ship an NSS module

An OIDC-backed `libnss_oidc.so` is deliberately **not** provided, because NSS is
a poor fit for OIDC:

- **Blast radius.** An NSS module is loaded into *every* process that resolves a
  name (sshd, sudo, systemd, login, even `ls`). A hang or crash degrades the
  whole host. NSS modules must be fast, non-blocking, and flawless.
- **NSS cannot do network I/O; OIDC is inherently network-bound.** `getpwnam`
  is synchronous and called constantly — you cannot run a device flow or token
  validation inside it. Any NSS module would have to serve from a locally
  materialized cache, which means you *still* need a provisioning/sync step.
  That undercuts the main reason to want NSS in the first place.
- **UID allocation is the hard part, and OIDC does not solve it.** OIDC tokens
  carry no POSIX UID unless you configure POSIX attributes in the directory
  (e.g. the AWS Identity Store). Inventing UIDs (hashing `sub`) risks collisions
  and instability; a central allocator needs shared state — which is precisely
  what LDAP/SSSD already provide.

This is the same conclusion reached by comparable systems (e.g. Google OS Login
ships an NSS module **plus** a guest agent that materializes a cache with
directory-assigned UIDs — even there, live lookups are not done in NSS).

#### When you have no directory at all

For pure-OIDC environments with no directory and ephemeral cloud nodes where you
will not run SSSD, the supported pattern is **provision-on-first-login**:
have the broker (or a front-end such as Open OnDemand) create the local account
with a deterministic UID before the PAM session, then let standard
`/etc/passwd` + `pam_mkhomedir` take over. The account then genuinely exists, so
`getpwnam` and all UID-dependent tooling work normally — without an in-process
NSS failure surface. oidc-pam itself does not perform this provisioning; wire it
into your boot/login automation.

## Prerequisites

### System Requirements

#### Minimum Requirements
- Linux server with PAM support
- **OpenSSH 7.7 or newer** on every host the broker provisions keys on
- 2 CPU cores
- 4 GB RAM
- 20 GB storage
- Network connectivity to OIDC provider

##### Why OpenSSH 7.7 is a hard requirement

The broker writes each login's key into `~/.ssh/authorized_keys` with an
`expiry-time="…"` option in front of it, so that **sshd** stops honouring the key
once it is stale. That is deliberate: the broker holds its sessions in memory, so
before this every key it had issued outlived the process that was meant to revoke
it (#171), and an expiry only the broker knows about is an expiry a restart
forgets.

`expiry-time=` was added in OpenSSH 7.7. An sshd that does not recognise an
authorized_keys option refuses the whole entry, so on anything older **every key
the broker installs is rejected**: the login is authenticated, the file looks
correct, and SSH still says `Permission denied (publickey)`. Check with:

```bash
ssh -V   # OpenSSH_8.4p1 …  -> fine
```

Versions the common platforms ship: RHEL/CentOS Stream 8 `8.0p1`, RHEL 9 `8.7p1`,
Debian 11 `8.4p1`, Debian 12 `9.2p1`, Ubuntu 20.04 `8.2p1`, Ubuntu 22.04 `8.9p1`,
Ubuntu 24.04 `9.6p1` — all fine. **Amazon Linux 2 and RHEL/CentOS 7 ship `7.4p1`
and cannot run this**; check any other platform with the command above before
deploying. The broker does not currently detect the local sshd version
([#199](https://github.com/scttfrdmn/oidc-pam/issues/199)); it writes the option
unconditionally.

The timespec itself is written in the host's local time zone, not UTC, because the
`Z` suffix that means UTC was only added in OpenSSH 9.1 and older versions reject
a timespec carrying it.

#### Recommended Requirements
- 4+ CPU cores
- 8+ GB RAM
- 50+ GB SSD storage
- High-availability network connection
- Load balancer for multiple instances

#### Supported Operating Systems
- Ubuntu 20.04 LTS or later (OpenSSH 8.2p1+)
- CentOS Stream 8 or later (8.0p1+)
- RHEL 8 or later (8.0p1+)
- Debian 11 or later (8.4p1+)
- SUSE Linux Enterprise Server 15+ — check `ssh -V` first; the older service packs
  predate OpenSSH 7.7
- **Not Amazon Linux 2, and not RHEL/CentOS 7**: both ship OpenSSH 7.4p1, which does
  not know `expiry-time=` and therefore refuses every key the broker installs. See
  the OpenSSH requirement above.

Which distribution has actually been tested, and on what, is in
[README.md](README.md#-supported-platforms) — the list above is what the broker's
dependencies allow, not a claim that a login has been run on each one.

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

### Method 2: Binary Installation (Recommended)

Release tarballs are named `oidc-pam-<version>-linux-<arch>.tar.gz` (with a
matching `.sha256`) and are published for `amd64` and `arm64`. Each archive
extracts to a versioned directory containing the four binaries, a `configs/`
tree, the docs, and an `install.sh` entrypoint.

```bash
VERSION=v0.3.2
ARCH=amd64   # or arm64

# Download the archive and its checksum
curl -fsSLO https://github.com/scttfrdmn/oidc-pam/releases/download/${VERSION}/oidc-pam-${VERSION}-linux-${ARCH}.tar.gz
curl -fsSLO https://github.com/scttfrdmn/oidc-pam/releases/download/${VERSION}/oidc-pam-${VERSION}-linux-${ARCH}.tar.gz.sha256

# Verify integrity
sha256sum -c oidc-pam-${VERSION}-linux-${ARCH}.tar.gz.sha256

# Extract and install
tar -xzf oidc-pam-${VERSION}-linux-${ARCH}.tar.gz
cd oidc-pam-${VERSION}-linux-${ARCH}

# Installs binaries, example config, and the systemd unit.
# PAM is left untouched unless you pass --configure-pam.
sudo ./install.sh                 # add --configure-pam to wire pam_oidc.so into sshd

# Verify installation
systemctl status oidc-auth-broker
```

The bundled `install.sh` places `oidc-auth-broker`, `oidc-pam-helper`, and
`oidc-admin` in `/usr/local/bin`, `pam_oidc.so` in `/lib/security`, an example
config in `/etc/oidc-auth/broker.yaml`, and the systemd unit in
`/etc/systemd/system`. It does **not** start the broker or modify PAM unless
`--configure-pam` is supplied, so it cannot lock you out on its own.

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
      # A literal, or "env:VAR_NAME", or "file:/path/to/secret"
      client_secret: "file:/etc/oidc-auth/client-secret"
      scopes: ["openid", "email", "profile", "groups"]

# Authentication policies
#
# A policy is selected by its name: "default" applies to every host, and any
# other name must match the hostname of the machine being logged into (exactly,
# or as a domain component — "production" matches "api.production.example.com").
# A policy whose name matches no host never applies; the broker logs a warning
# naming it at startup. Policies cannot be scoped to an operation such as sudo.
#
# Every matching policy applies: require_groups is the union of the global
# authentication.require_groups and every match's, and max_session_duration is
# the smallest of them.
authentication:
  # Applies everywhere, whatever the host is called.
  require_groups: ["employees"]
  max_concurrent_sessions: 3

  policies:
    default:
      require_groups: ["employees", "contractors"]
      max_session_duration: "8h"
      audit_level: "standard"

    # Applies only on hosts named "admin", e.g. admin.example.com.
    admin:
      require_groups: ["administrators", "sysadmins"]
      max_session_duration: "4h"
      require_additional_mfa: true
      require_device_trust: true
      audit_level: "detailed"

# Security settings
security:
  # base64-encoded 32-byte key, from `oidc-admin gen-key`
  token_encryption_key: "file:/etc/oidc-auth/token-encryption-key"
  max_token_age: "24h"
  clock_skew_tolerance: "5m"
  rate_limiting:
    max_requests_per_minute: 60   # per requested account, not host-wide
    max_concurrent_auths: 10

# Server: the broker listens on a Unix socket, not a TCP port. There is no
# bind address and no HTTP API; metrics are the one optional TCP listener.
server:
  socket_path: "/var/run/oidc-auth/broker.sock"
  log_level: "info"
  metrics_addr: "127.0.0.1:9090"   # Prometheus /metrics; empty disables it

# Audit trail
audit:
  enabled: true
  format: "json"
  overflow_strategy: "block"       # block | sync | drop — see below
  outputs:
    - type: "file"                 # file | stdout | syslog | http
      path: "/var/log/oidc-auth/audit.log"
      rotation: "daily"
```

Every key a configuration file may contain is a field of `config.Config`. Since
#170 the broker refuses to start on a key it does not read and names the key's
full path, so nothing in the file can be a setting that does nothing. If an
upgrade rejects a file you cannot edit immediately, setting
`OIDC_AUTH_ALLOW_UNKNOWN_CONFIG_KEYS=true` in the unit downgrades the refusal to
a warning that lists the keys.

### 3. PAM Configuration

**Wire `pam_oidc.so` into one service's file at a time, and never into
`/etc/pam.d/common-auth` (Debian/Ubuntu) or `/etc/pam.d/system-auth` (RHEL,
Fedora, SUSE).** Those are `@include`d by every PAM service on the host, so a
module there runs for `su`, `sudo`, `gdm`/`sddm`, `polkit`, `login`, `cron` and
everything else linked against libpam. Each would then wait up to `timeout`
seconds (90 by default) for a human with a phone, and several can never satisfy a
device flow at all: no controlling terminal, a conversation function that discards
`PAM_TEXT_INFO`, or a graphical prompt that renders the QR code as ASCII art. The
stacks fail closed, so nothing is admitted that should not be — but the host
becomes unusable, and these stacks have no password fallback.

Only `sshd` is exercised end-to-end by CI (`test/e2e`). The `login`, `su` and
`sudo` files in `configs/pam/` are examples: deploy them one at a time, from a
host you can still get back into.

#### SSH Configuration (`/etc/pam.d/ssh`)
```bash
# Production SSH PAM configuration.
# Nothing may follow `requisite pam_deny.so`: it returns immediately, so this
# stack is OIDC-only. See "PAM stack semantics" below before changing it.
auth    sufficient  pam_oidc.so
auth    requisite   pam_deny.so

account optional    pam_oidc.so
account required    pam_unix.so
account required    pam_access.so

session required    pam_unix.so
session optional    pam_oidc.so
session required    pam_systemd.so
session optional    pam_env.so
```

#### Sudo Configuration (`/etc/pam.d/sudo`)
```bash
# Production sudo PAM configuration
auth    sufficient  pam_oidc.so
auth    requisite   pam_deny.so

account optional    pam_oidc.so
account required    pam_unix.so
account required    pam_access.so
account required    pam_time.so

session required    pam_unix.so
session optional    pam_oidc.so
session optional    pam_systemd.so
```

#### PAM stack semantics

**All authorization happens in the `auth` phase.** `pam_sm_authenticate` is where
the module talks to the broker, and the broker is where identity binding
(`username_claim`), `require_groups`, risk policy and session limits are
enforced. If the auth phase returns success, the user is authorized.

**`pam_oidc.so` has no `account`-phase opinion** and returns `PAM_IGNORE` there —
PAM does not count an ignored module toward the stack's result, so the account
modules after it decide. Two consequences:

- Use **`account optional pam_oidc.so`**, never `account sufficient`. A
  `sufficient` module that returns success short-circuits the rest of the account
  stack; earlier versions of this module returned `PAM_SUCCESS`, so `account
  sufficient pam_oidc.so` silently disabled every account check after it —
  `pam_time`, `pam_nologin`, `pam_access`, account expiry, `pam_unix`'s shadow
  checks. If your `/etc/pam.d/*` still says `account sufficient pam_oidc.so`,
  change it.
- **Keep a real account module in the stack.** With `pam_oidc.so` as the only
  account module, every module ignores and Linux-PAM returns
  `PAM_PERM_DENIED` — it fails closed rather than admitting everyone, but the
  account phase then decides nothing useful. The examples above pair it with
  `pam_unix.so` and `pam_access.so`.

**`password`** likewise: the module cannot change a password (change it at the
identity provider) and returns `PAM_AUTHTOK_ERR`. List it as `optional` so it
does not block password changes for local accounts.

**Nothing may follow `requisite pam_deny.so`.** `requisite` returns to the
application immediately on failure, so a `pam_unix.so` line after it is dead
configuration, not an emergency fallback. To allow Unix passwords when the broker
or IdP is unavailable, remove `pam_deny.so` and let `pam_unix.so` decide —
accepting that a user with a local password then bypasses all OIDC policy. The
more common arrangement is to leave this stack OIDC-only and keep SSH public-key
access as the break-glass path, since sshd's pubkey authentication does not
consult the PAM auth stack at all.

### 4. System Service Configuration

#### Systemd Service (`/etc/systemd/system/oidc-auth-broker.service`)

The unit shipped in `configs/systemd/oidc-auth-broker.service` is the reference; install
that rather than retyping it. It looks like this:

```ini
[Unit]
Description=OIDC Authentication Broker
After=network.target
Wants=network.target

[Service]
Type=simple
# root, not a service account: the broker installs each login's SSH key in that
# account's ~/.ssh/authorized_keys and hands the file to the account, which needs
# both write access to the home directory and the ability to chown.
User=root
Group=root
ExecStart=/usr/local/bin/oidc-auth-broker --config /etc/oidc-auth/broker.yaml
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
# Must stay off. ProtectHome=true replaces /home with an empty tmpfs for this
# service, so no authorized_keys can be written at all (#171).
ProtectHome=false
# ProtectSystem=strict makes everything read-only, so every path the broker
# writes is listed: its runtime socket, its logs, its state directory (issued keys
# and per-user locks), and the home directories it provisions keys into. Add your
# own home path here if homes are not under /home. The "-" prefix makes a missing
# path non-fatal: without it systemd refuses to start the unit at all on a host
# that has no /home, which is exactly the host whose homes are somewhere else.
ReadWritePaths=/var/run/oidc-auth /var/log/oidc-auth /etc/oidc-auth /var/lib/oidc-pam -/home
StateDirectory=oidc-pam
StateDirectoryMode=0700
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Environment
Environment=GOMAXPROCS=2
Environment=GOGC=100

[Install]
WantedBy=multi-user.target
```

If a login reports success but the SSH key does not work, check these three things
first: that `ProtectHome` is not `true`, that the path homes really live on is in
`ReadWritePaths`, and that `/var/lib/oidc-pam` exists and is writable. A key the
broker could not install now denies the login rather than completing it, and the
reason is recorded as an `ssh_key_provisioning_failed` audit event.

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

The broker serves `/metrics` only when `server.metrics_addr` is set; there is no
default and no listener otherwise. Bind it to a loopback or management address —
the endpoint has no authentication.

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

# Check what the broker itself thinks
sudo oidc-admin status
sudo oidc-admin sessions
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

## Administrative CLI (`oidc-admin`)

`oidc-admin` asks the running broker about its own state over the same Unix
socket the PAM module uses. **Every command that talks to the broker must be run
as root** (`sudo`): the socket accepts connections only from uid 0, so an
unprivileged invocation is refused by the broker, not by the CLI.

```bash
# Is the broker running, and since when?
sudo oidc-admin status

# Detailed local checks: socket, config file, providers
sudo oidc-admin health

# Who is logged in, and which device flows are still pending?
sudo oidc-admin sessions

# Which broker-managed SSH keys exist, how strong are they, when do they expire?
sudo oidc-admin keys

# Generate a token_encryption_key (does not talk to the broker)
oidc-admin gen-key
```

If the broker listens somewhere other than the default
`/var/run/oidc-auth/broker.sock`, point the CLI at it with
`OIDC_SOCKET_PATH=/path/to/broker.sock`.

`sessions` lists pending device flows as well as authenticated sessions:

| Status | Meaning |
|---|---|
| `pending` | The device flow has started; the user has not completed it. Grants nothing. |
| `active` | Authenticated. Identity binding and `require_groups` have passed. |
| `expired` | Past its lifetime but not yet removed by the 5-minute cleanup sweep. Not usable. |

A login that appears to hang is usually a `pending` row here — that tells you the
request reached the broker and is waiting on the user, rather than failing before
it got that far.

Nothing in this output is a credential: sessions are listed without their tokens
(which live encrypted in the broker's token store) and keys are listed without
their key material.

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

# Enable debug mode: set server.log_level to "debug" in
# /etc/oidc-auth/broker.yaml, then restart the broker
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

## GeoIP Database Setup

Geographic access restrictions (`geo_restrictions` in the configuration) require a MaxMind GeoLite2 Country database. Without a database, the policy engine cannot resolve country codes, and any `allowed_countries` restriction will deny all access.

### Obtaining the Database

1. Register for a free MaxMind account at <https://www.maxmind.com/en/geolite2/signup>
2. Generate a license key in your account portal
3. Download the **GeoLite2-Country** database in `.mmdb` format:

   ```bash
   # Using the official geoipupdate tool (recommended for automatic updates)
   sudo apt-get install geoipupdate          # Debian/Ubuntu
   sudo dnf install geoipupdate             # RHEL/Fedora

   # Configure /etc/GeoIP.conf:
   # AccountID  <your-account-id>
   # LicenseKey <your-license-key>
   # EditionIDs GeoLite2-Country

   sudo geoipupdate
   # Database is written to /usr/share/GeoIP/GeoLite2-Country.mmdb
   ```

   Or download manually:

   ```bash
   curl -o GeoLite2-Country.mmdb.tar.gz \
     "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_KEY&suffix=tar.gz"
   tar -xzf GeoLite2-Country.mmdb.tar.gz --strip-components=1 --wildcards '*.mmdb'
   sudo install -m 644 GeoLite2-Country.mmdb /usr/share/GeoIP/GeoLite2-Country.mmdb
   ```

### Configuration

Set `geoip_database_path` in the `authentication` section of your configuration file:

```yaml
authentication:
  geoip_database_path: /usr/share/GeoIP/GeoLite2-Country.mmdb
  time_based_policies:
    geo_restrictions:
      - allowed_countries: [US, CA, GB]
```

The broker will fail to start if the path is set but the file cannot be opened.

### Notes

- The GeoLite2 database is updated monthly by MaxMind. Set up `geoipupdate` as a cron job or systemd timer to keep it current.
- Private, loopback, and link-local addresses always return an empty country code and are unaffected by geo restrictions.
- If `geoip_database_path` is not set, `getCountryFromIP` returns `""`. Any `allowed_countries` restriction will then block access, so **do not configure geo restrictions without also setting a database path**.

---

This deployment guide provides comprehensive instructions for production deployment of the OIDC PAM authentication system. Always test thoroughly in a non-production environment before deploying to production.