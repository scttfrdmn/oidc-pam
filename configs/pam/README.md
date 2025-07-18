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
auth    sufficient  pam_oidc.so config=/etc/oidc-auth/broker.yaml
auth    required    pam_unix.so try_first_pass
```

### OIDC-Only Authentication
```
auth    required    pam_oidc.so config=/etc/oidc-auth/broker.yaml
```

### Unix-First with OIDC Fallback
```
auth    sufficient  pam_unix.so
auth    required    pam_oidc.so config=/etc/oidc-auth/broker.yaml
```

### Debug Mode
```
auth    sufficient  pam_oidc.so config=/etc/oidc-auth/broker.yaml debug
```

## PAM Module Parameters

### Common Parameters
- `config=/path/to/config.yaml` - Path to OIDC broker configuration
- `debug` - Enable debug logging
- `operation=operation_name` - Specify operation type (ssh, sudo, su, etc.)
- `target_user=%u` - Pass target username for authorization

### Service-Specific Parameters
- **SSH**: `service=ssh`
- **Sudo**: `operation=sudo target_user=%u`
- **Su**: `operation=su target_user=%u`
- **Login**: `service=login`

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
auth    sufficient  pam_oidc.so config=/etc/oidc-auth/broker.yaml debug

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