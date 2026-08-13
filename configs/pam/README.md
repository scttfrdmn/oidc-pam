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

## PAM Module Parameters

`pam_oidc.so` accepts exactly two arguments:

| Argument | Meaning |
|---|---|
| `debug` | Log at `LOG_DEBUG` to syslog (`LOG_AUTHPRIV`). Remove in production. |
| `socket=<path>` | Absolute path to the broker's Unix socket. Defaults to `/var/run/oidc-auth/broker.sock`, matching the broker's own default for `server.socket_path`. Only needed if you changed that. |

Anything else is ignored and logged at `LOG_WARNING`, so a typo shows up in
`/var/log/auth.log` instead of silently doing nothing.

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
ChallengeResponseAuthentication yes
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