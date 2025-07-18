# OIDC PAM Authentication - Quick Start Guide

This guide will help you quickly set up and test the OIDC PAM authentication system in your environment.

## ⚠️ Alpha Release Notice

This is an **alpha release** intended for testing and evaluation purposes only. Do not use in production environments without thorough testing and security review.

## Prerequisites

### System Requirements
- Linux system with PAM support (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- Go 1.21+ (for building from source)
- Docker and Docker Compose (for testing with Keycloak)
- Root or sudo access for PAM configuration

### OIDC Provider
You'll need an OIDC provider configured with:
- Device authorization flow support
- User groups/roles for authorization
- SSH public key attributes (for SSH authentication)

## Quick Installation

### Option 1: Download Pre-built Binaries

```bash
# Download the latest alpha release
curl -L https://github.com/yourusername/oidc-pam/releases/latest/download/oidc-pam-linux-amd64.tar.gz -o oidc-pam.tar.gz

# Extract and install
tar -xzf oidc-pam.tar.gz
sudo ./install.sh
```

### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/oidc-pam.git
cd oidc-pam

# Build the project
make build

# Install binaries
sudo make install
```

## Quick Test Setup with Keycloak

### 1. Start Keycloak Test Environment

```bash
# Start Keycloak with test configuration
docker-compose -f docker-compose.test.yml up -d

# Wait for Keycloak to start
docker-compose -f docker-compose.test.yml logs -f keycloak
```

### 2. Configure OIDC Broker

```bash
# Copy example configuration
sudo cp configs/production/broker-minimal.yaml /etc/oidc-auth/broker.yaml

# Edit configuration for Keycloak
sudo nano /etc/oidc-auth/broker.yaml
```

Update the configuration:
```yaml
oidc:
  providers:
    - name: "keycloak"
      issuer: "http://localhost:8080/realms/test-realm"
      client_id: "oidc-pam-client"
      client_secret: "test-secret"
      scopes: ["openid", "email", "profile", "groups"]

logging:
  level: "info"
  audit_level: "detailed"
  
security:
  encryption_key: "your-32-character-encryption-key"
```

### 3. Start OIDC Broker

```bash
# Start the broker
sudo systemctl start oidc-auth-broker

# Check status
sudo systemctl status oidc-auth-broker

# View logs
sudo journalctl -u oidc-auth-broker -f
```

### 4. Test Authentication

```bash
# Test authentication flow
./test-broker

# Test with SSH (if configured)
ssh testuser@localhost
```

## Basic Configuration

### 1. OIDC Provider Configuration

Edit `/etc/oidc-auth/broker.yaml`:

```yaml
oidc:
  providers:
    - name: "primary"
      issuer: "https://your-oidc-provider.com"
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      scopes: ["openid", "email", "profile", "groups"]
      device_flow_enabled: true

authentication:
  policies:
    default:
      require_groups: ["users"]
      session_duration: "8h"
      audit_level: "standard"

logging:
  level: "info"
  audit_level: "detailed"
  audit_file: "/var/log/oidc-auth/audit.log"

security:
  encryption_key: "generate-a-32-character-key-here"
  token_cache_duration: "1h"
```

### 2. PAM Configuration

For SSH authentication, edit `/etc/pam.d/ssh`:

```
# OIDC authentication
auth    sufficient  pam_oidc.so config=/etc/oidc-auth/broker.yaml service=ssh
auth    requisite   pam_deny.so
auth    required    pam_unix.so try_first_pass

# Account management
account required    pam_oidc.so config=/etc/oidc-auth/broker.yaml
account required    pam_unix.so

# Session management
session required    pam_unix.so
session optional    pam_oidc.so config=/etc/oidc-auth/broker.yaml
```

### 3. SSH Configuration

Edit `/etc/ssh/sshd_config`:

```
# Enable PAM authentication
UsePAM yes
ChallengeResponseAuthentication yes
PasswordAuthentication no
PubkeyAuthentication yes
```

Restart SSH service:
```bash
sudo systemctl restart sshd
```

## Testing

### 1. Test OIDC Provider Connectivity

```bash
# Test OIDC discovery
curl -k https://your-oidc-provider.com/.well-known/openid-configuration

# Test broker connectivity
sudo systemctl status oidc-auth-broker
```

### 2. Test Authentication Flow

```bash
# Test with the test utility
./test-broker

# Expected output:
# Starting authentication flow...
# Device code: ABCD-EFGH
# User code: ABCD-EFGH
# Verification URL: https://your-oidc-provider.com/device
# Please visit the URL and enter the code
# Waiting for user authorization...
# Authentication successful!
```

### 3. Test SSH Authentication

```bash
# Test SSH connection
ssh your-oidc-username@localhost

# Expected flow:
# 1. SSH prompts for authentication
# 2. OIDC device flow initiated
# 3. User visits verification URL
# 4. User enters code and authenticates
# 5. SSH session established
```

## Troubleshooting

### Common Issues

#### 1. Broker Won't Start
```bash
# Check broker logs
sudo journalctl -u oidc-auth-broker -f

# Check configuration
sudo oidc-auth-broker --config /etc/oidc-auth/broker.yaml --validate
```

#### 2. Authentication Fails
```bash
# Enable debug mode
# Edit /etc/oidc-auth/broker.yaml
logging:
  level: "debug"

# Restart broker
sudo systemctl restart oidc-auth-broker

# Check detailed logs
sudo journalctl -u oidc-auth-broker -f
```

#### 3. SSH Authentication Issues
```bash
# Check SSH logs
sudo tail -f /var/log/auth.log

# Check PAM configuration
sudo pam-config --verify

# Test PAM module directly
sudo pamtester ssh your-username authenticate
```

#### 4. OIDC Provider Connectivity
```bash
# Test network connectivity
curl -v https://your-oidc-provider.com/.well-known/openid-configuration

# Check DNS resolution
nslookup your-oidc-provider.com

# Check SSL/TLS certificates
openssl s_client -connect your-oidc-provider.com:443
```

### Debug Mode

Enable debug logging in `/etc/oidc-auth/broker.yaml`:

```yaml
logging:
  level: "debug"
  audit_level: "detailed"
  audit_file: "/var/log/oidc-auth/audit.log"
```

Add debug to PAM configuration:
```
auth    sufficient  pam_oidc.so config=/etc/oidc-auth/broker.yaml debug
```

## Next Steps

### 1. Configure Your OIDC Provider
- Set up user groups and roles
- Configure SSH public key attributes
- Enable device authorization flow
- Set up proper scopes and claims

### 2. Implement Security Policies
- Review and customize authentication policies
- Configure group-based access controls
- Set up time-based access restrictions
- Enable comprehensive audit logging

### 3. Production Deployment
- Review security configurations
- Set up monitoring and alerting
- Implement backup and recovery procedures
- Conduct security testing

### 4. User Management
- Create user onboarding documentation
- Set up user support procedures
- Train users on authentication flow
- Implement user lifecycle management

## Support and Documentation

### Additional Resources
- [Deployment Guide](DEPLOYMENT.md)
- [Configuration Guide](configs/README.md)
- [PAM Configuration Examples](configs/pam/README.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)

### Getting Help
- Check the [troubleshooting guide](TROUBLESHOOTING.md)
- Review system logs (`/var/log/auth.log`, `/var/log/oidc-auth/`)
- Enable debug mode for detailed logging
- Contact your system administrator

## Security Considerations

### Important Security Notes
1. **Test Thoroughly**: This is alpha software - test extensively before production use
2. **Backup Access**: Always maintain emergency access methods (root console, SSH keys)
3. **Monitor Logs**: Enable comprehensive logging and monitoring
4. **Regular Updates**: Keep the system updated with security patches
5. **Access Controls**: Implement proper group-based access controls

### Emergency Access
If OIDC authentication fails:
1. Access via root console
2. SSH with public key authentication
3. Boot to single-user mode
4. Use emergency admin account

## Feedback and Contributions

This is an alpha release and we welcome feedback:
- Report issues on GitHub
- Suggest improvements
- Contribute configuration examples
- Share deployment experiences

## License

This project is licensed under the MIT License. See LICENSE file for details.

---

**Remember**: This is alpha software intended for testing and evaluation only. Do not use in production without thorough security review and testing.