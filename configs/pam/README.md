# PAM Configuration Files for OIDC Authentication

This directory contains example PAM configuration files for integrating OIDC authentication with various system services.

## ⚠️ Important Security Notice

**These configurations can affect system security and access. Always:**
1. Test on non-production systems first
2. Keep emergency access methods available
3. Backup existing configurations
4. Test thoroughly before deploying to production

## Configuration Files

### Core Authentication
- **`common-auth`** - Common authentication stack for Debian/Ubuntu systems
- **`ssh`** - SSH daemon authentication configuration
- **`login`** - Console/TTY login authentication
- **`su`** - Switch user authentication
- **`sudo`** - Sudo privilege escalation authentication

### Usage Instructions

#### 1. Prerequisites
- OIDC PAM module installed: `/lib/security/pam_oidc.so`
- OIDC broker running: `systemctl start oidc-auth-broker`
- OIDC provider configured in `/etc/oidc-auth/broker.yaml`

#### 2. Installation

**Backup existing configurations:**
```bash
sudo cp -r /etc/pam.d /etc/pam.d.backup
```

**Install configurations:**
```bash
# For specific services
sudo cp configs/pam/ssh /etc/pam.d/ssh
sudo cp configs/pam/sudo /etc/pam.d/sudo

# For system-wide (be careful!)
sudo cp configs/pam/common-auth /etc/pam.d/common-auth
```

#### 3. Testing

**Always test with a non-privileged user first:**
```bash
# Test SSH authentication
ssh testuser@localhost

# Test sudo
sudo -l

# Test su
su - testuser
```

**Keep emergency access open:**
```bash
# Keep a root session open
sudo -i

# Or maintain SSH access with public keys
ssh -i ~/.ssh/id_rsa root@localhost
```

## Configuration Options

### Basic OIDC Authentication
```
auth    sufficient  pam_oidc.so
auth    required    pam_unix.so try_first_pass
```

### OIDC-Only Authentication
```
auth    required    pam_oidc.so
```

### Unix-First with OIDC Fallback
```
auth    sufficient  pam_unix.so
auth    required    pam_oidc.so
```

### Debug Mode
```
auth    sufficient  pam_oidc.so debug
```

## Which PAM phases the module participates in

`pam_oidc.so` implements one decision, in the `auth` phase. Everything the
module is for — talking to the broker, which enforces identity binding
(`username_claim`), `require_groups`, risk policy and session limits — happens in
`pam_sm_authenticate`. The other phases are listed below with the control flag to
use and why.

| Phase | Use | What the module does |
|---|---|---|
| `auth` | `sufficient` or `required` | The real decision. Runs the device flow, waits for it, and returns success only once the broker has authorized the login. |
| `account` | **`optional`** | Nothing: returns `PAM_IGNORE`. |
| `session` | `optional` | Logs session open/close. No decision. |
| `password` | `optional` | Cannot change a password; returns `PAM_AUTHTOK_ERR`. |

### Why `account optional`, never `account sufficient`

The module returns `PAM_IGNORE` from `pam_sm_acct_mgmt` — "I have no opinion" —
so PAM does not count it toward the account stack's result and the modules after
it decide.

Earlier versions returned `PAM_SUCCESS` instead, and the example configs used
`account sufficient pam_oidc.so`. A `sufficient` module that succeeds
short-circuits the rest of the phase, so that combination silently disabled every
account check after it: `pam_time`, `pam_nologin`, `pam_access`, account expiry,
`pam_unix`'s shadow checks. The module was answering a question it never asked,
and rubber-stamping the account phase for every user. **If your `/etc/pam.d/*`
files still say `account sufficient pam_oidc.so`, change them to `optional`.**

Keep at least one real account module in the stack. If `pam_oidc.so` is the only
one, every module ignores and Linux-PAM returns `PAM_PERM_DENIED`: it fails
closed rather than admitting everyone, but nothing useful is being checked. The
shipped configs pair it with `pam_unix.so` plus `pam_access.so`/`pam_time.so`.

### Nothing may follow `requisite pam_deny.so`

`requisite` returns to the application immediately on failure, so in

```
auth    sufficient  pam_oidc.so
auth    requisite   pam_deny.so
auth    required    pam_unix.so try_first_pass   # never reached
```

the third line is dead configuration, not an emergency fallback — the shipped
`ssh`, `su` and `sudo` examples used to carry exactly that line and describe it as
one. These stacks are OIDC-only: if OIDC authentication fails, the login is
refused.

To allow Unix passwords when the broker or IdP is unavailable, drop
`pam_deny.so`:

```
auth    sufficient  pam_oidc.so
auth    required    pam_unix.so try_first_pass nullok_secure
```

The trade-off is real: a user with a local password then bypasses every OIDC
policy. The usual alternative is to keep the stack OIDC-only and rely on SSH
public-key authentication as the break-glass path, since sshd's pubkey path does
not consult the PAM auth stack at all.

## PAM Module Parameters

`pam_oidc.so` accepts exactly three arguments:

| Argument | Meaning |
|---|---|
| `debug` | Log at `LOG_DEBUG` to syslog (`LOG_AUTHPRIV`). Remove in production. |
| `socket=<path>` | Absolute path to the broker's Unix socket. Defaults to `/var/run/oidc-auth/broker.sock`, matching the broker's own default for `server.socket_path`. Only needed if you changed that. |
| `timeout=<seconds>` | How long to wait for the user to finish the device flow before refusing the login. Default `90`, accepted range `10`–`900`. |

Anything else is ignored and logged at `LOG_WARNING`, so a typo shows up in
`/var/log/auth.log` instead of silently doing nothing.

### How the wait works

The module prompts with the verification URL and user code, then polls the broker
until the flow completes, is refused, or `timeout` expires. **The login is
refused when the timeout expires** — an unfinished device flow is never a
success.

The default `timeout` of 90 s is deliberately below sshd's default
`LoginGraceTime` of 120 s: sshd kills the connection when the grace time runs
out, which would look like a hang rather than a denial. If you raise `timeout`,
raise `LoginGraceTime` in `/etc/ssh/sshd_config` to match:

```
# /etc/pam.d/sshd
auth    sufficient  pam_oidc.so timeout=300

# /etc/ssh/sshd_config
LoginGraceTime 330
```

### Arguments that do *not* exist

Earlier versions of these example configs passed parameters the module has never
implemented. They were silently discarded; they are now logged as unrecognized:

- `config=/path/to/broker.yaml` — the module reads no configuration file. It
  talks to the broker over the socket, and the broker reads `broker.yaml`
  itself. Still accepted (with a warning) so existing PAM stacks keep working.
- `operation=sudo`, `target_user=%u`, `service=ssh` — no such authorization
  knobs exist in the module. Note also that PAM does **not** expand `%u` in
  module arguments; it would have been passed through literally. The service
  name and target user already reach the broker: the module reads them from
  `PAM_SERVICE` and `pam_get_user()` and sends them in the request. Configure
  per-service policy in `broker.yaml`, not in the PAM line.

## Security Considerations

### 1. Emergency Access
Always maintain emergency access methods:
- Root console access
- SSH with public key authentication
- Emergency user account with Unix password
- Single-user mode boot capability

### 2. Access Controls
Implement proper access controls:
- Group-based authorization in OIDC provider
- Network-based restrictions
- Time-based access controls
- Resource-based policies

### 3. Monitoring
Monitor authentication events:
```bash
# Watch authentication logs
sudo tail -f /var/log/auth.log

# Monitor OIDC audit logs
sudo tail -f /var/log/oidc-auth/audit.log

# Check PAM configuration
sudo pam-config --verify
```

### 4. Backup and Recovery
Maintain backup procedures:
```bash
# Backup PAM configuration
sudo tar -czf pam-config-backup.tar.gz /etc/pam.d/

# Test backup restoration
sudo tar -xzf pam-config-backup.tar.gz -C /tmp/
```

## Troubleshooting

### Common Issues

#### 1. Authentication Failures
```bash
# Check OIDC broker status
sudo systemctl status oidc-auth-broker

# Check OIDC broker logs
sudo journalctl -u oidc-auth-broker -f

# Test OIDC provider connectivity
curl -k https://your-oidc-provider.com/.well-known/openid-configuration
```

#### 2. PAM Module Not Found
```bash
# Check if module is installed
ls -la /lib/security/pam_oidc.so

# Check module permissions
sudo chmod 644 /lib/security/pam_oidc.so
```

#### 3. Configuration Errors
```bash
# Validate PAM configuration
sudo pam-config --verify

# Check configuration syntax
sudo pam-config --check /etc/pam.d/ssh
```

#### 4. Debug Authentication Flow
```bash
# Enable debug mode
auth    sufficient  pam_oidc.so debug

# Check detailed logs
sudo journalctl -f | grep pam_oidc
```

### Emergency Recovery

#### 1. Boot to Single-User Mode
```bash
# During boot, add to kernel command line
single

# Or
systemd.unit=rescue.target
```

#### 2. Restore from Backup
```bash
# Boot from rescue media
sudo mount /dev/sda1 /mnt
sudo cp -r /mnt/etc/pam.d.backup/* /mnt/etc/pam.d/
sudo umount /mnt
```

#### 3. Disable PAM Module
```bash
# Comment out pam_oidc.so lines
sudo sed -i 's/^auth.*pam_oidc.so/#&/' /etc/pam.d/ssh
```

## Best Practices

### 1. Gradual Rollout
1. Start with non-critical services
2. Test with limited user groups
3. Monitor authentication patterns
4. Gradually expand to all services

### 2. Configuration Management
```bash
# Use configuration management tools
# Ansible, Puppet, Chef, etc.

# Version control PAM configurations
git add /etc/pam.d/
git commit -m "Add OIDC PAM configuration"
```

### 3. Testing Procedures
1. Create test users in OIDC provider
2. Test successful authentication scenarios
3. Test failed authentication scenarios
4. Test emergency access methods
5. Test during OIDC provider outages

### 4. Documentation
- Document all changes
- Maintain configuration inventory
- Create runbooks for common issues
- Train operations team on troubleshooting

## Integration Examples

### With SSH
```bash
# /etc/ssh/sshd_config
UsePAM yes

# The device-flow prompt reaches the user over keyboard-interactive
# authentication. This directive was named ChallengeResponseAuthentication
# before OpenSSH 8.7, which still accepts that spelling as a deprecated alias.
KbdInteractiveAuthentication yes

PasswordAuthentication no
PubkeyAuthentication yes
```

### With Sudo
```bash
# /etc/sudoers
%oidc-admin ALL=(ALL:ALL) ALL
%oidc-operators ALL=(ALL) NOPASSWD: /usr/bin/systemctl
```

### With Access Controls
```bash
# /etc/security/access.conf
+ : oidc-users : LOCAL
+ : oidc-users : 192.168.1.0/24
- : ALL : ALL
```

## Compliance Considerations

### Audit Requirements
- Log all authentication attempts
- Implement session recording for privileged access
- Maintain audit trails for compliance
- Regular review of access patterns

### Security Standards
- Implement principle of least privilege
- Use strong authentication methods
- Regular security assessments
- Compliance with organizational policies

## Support

For additional support:
- Check the main configuration guide: `../CONFIGURATION-GUIDE.md`
- Review troubleshooting documentation
- Consult system logs for detailed error messages
- Contact system administrators for assistance

## Contributing

To contribute PAM configuration improvements:
1. Test configurations thoroughly
2. Document all changes
3. Provide clear examples
4. Include troubleshooting information
5. Submit pull requests with detailed descriptions