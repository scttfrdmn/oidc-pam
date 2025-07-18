# OIDC PAM Configuration Guide

This guide provides comprehensive instructions for configuring the OIDC PAM authentication system for different environments and providers.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Configuration Templates](#configuration-templates)
3. [Provider-Specific Setup](#provider-specific-setup)
4. [Security Best Practices](#security-best-practices)
5. [Environment-Specific Configurations](#environment-specific-configurations)
6. [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Choose Your Configuration Template

Select the appropriate template based on your environment:

- **`broker-minimal.yaml`** - Simple production setup with security defaults
- **`broker-enterprise.yaml`** - Enterprise setup with advanced features
- **`broker-cloud.yaml`** - Cloud-native deployment with environment variables

### 2. Configure Your OIDC Provider

Choose your provider and follow the specific setup guide:

- **Keycloak** - See `providers/keycloak.yaml`
- **Azure AD** - See `providers/azure-ad.yaml`
- **Okta** - See `providers/okta.yaml`

### 3. Basic Setup Steps

1. **Install the system:**
   ```bash
   sudo ./install.sh
   ```

2. **Copy and edit configuration:**
   ```bash
   sudo cp configs/production/broker-minimal.yaml /etc/oidc-auth/broker.yaml
   sudo nano /etc/oidc-auth/broker.yaml
   ```

3. **Generate encryption key:**
   ```bash
   openssl rand -base64 32
   ```

4. **Update configuration with your settings:**
   - OIDC provider URL
   - Client ID and secret
   - Required groups
   - Encryption key

5. **Start the service:**
   ```bash
   sudo systemctl start oidc-auth-broker
   sudo systemctl enable oidc-auth-broker
   ```

## Configuration Templates

### Minimal Production (`broker-minimal.yaml`)

**Use for:**
- Simple deployments
- Single OIDC provider
- Basic security requirements
- Small to medium organizations

**Features:**
- Essential security settings
- Basic audit logging
- Single provider configuration
- Minimal dependencies

**Configuration Required:**
```yaml
oidc:
  providers:
    - name: "primary"
      issuer: "https://your-oidc-provider.com"
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      scopes: ["openid", "email", "profile", "groups"]

security:
  token_encryption_key: "CHANGE-THIS-TO-A-SECURE-32-BYTE-KEY"

authentication:
  require_groups: ["linux-users"]
```

### Enterprise Production (`broker-enterprise.yaml`)

**Use for:**
- Large organizations
- Multiple OIDC providers
- Advanced security requirements
- Compliance needs (SOC2, HIPAA, PCI-DSS)

**Features:**
- Multiple provider support
- Advanced policy engine
- Comprehensive audit logging
- Risk-based authentication
- Time-based access controls
- Network security requirements

**Key Sections:**
- Multiple OIDC providers (primary, backup, service accounts)
- Environment-specific policies (production, staging, development)
- Advanced security settings
- Comprehensive audit configuration
- SSH key management
- Policy engine configuration

### Cloud-Native (`broker-cloud.yaml`)

**Use for:**
- Kubernetes deployments
- Container orchestration
- Cloud-native applications
- Microservices architectures

**Features:**
- Environment variable configuration
- Cloud provider integration (AWS, Azure, GCP)
- Container-friendly logging
- Health checks and metrics
- Kubernetes deployment examples

**Environment Variables:**
```bash
OIDC_ISSUER_URL=https://your-provider.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
TOKEN_ENCRYPTION_KEY=your-encryption-key
```

## Provider-Specific Setup

### Keycloak Setup

1. **Create Realm:**
   - Admin Console → Add realm
   - Name: `company`

2. **Create Client:**
   - Client ID: `oidc-pam-client`
   - Access Type: `confidential`
   - Enable: Standard Flow, Direct Access Grants, Service Accounts
   - Enable: OAuth 2.0 Device Authorization Grant

3. **Configure Scopes:**
   - Add `groups` scope
   - Configure group membership mapper

4. **Create Groups:**
   - `linux-users`
   - `administrators`
   - `developers`

**Configuration:**
```yaml
oidc:
  providers:
    - name: "keycloak-primary"
      issuer: "https://keycloak.example.com/realms/company"
      client_id: "oidc-pam-client"
      client_secret: "your-client-secret"
      user_mapping:
        username_claim: "preferred_username"
        groups_claim: "groups"
```

### Azure AD Setup

1. **Register Application:**
   - Azure Portal → Azure Active Directory → App registrations
   - Name: `OIDC PAM Client`
   - Account types: `Single tenant`

2. **Configure Authentication:**
   - Enable public client flows
   - Add platform configurations

3. **Set API Permissions:**
   - Microsoft Graph: `User.Read`, `Group.Read.All`
   - Grant admin consent

4. **Configure Token:**
   - Add optional claims: email, groups
   - Configure group claims

**Configuration:**
```yaml
oidc:
  providers:
    - name: "azure-ad-primary"
      issuer: "https://login.microsoftonline.com/your-tenant-id/v2.0"
      client_id: "your-azure-app-id"
      client_secret: "your-azure-app-secret"
      scopes: ["openid", "profile", "email", "https://graph.microsoft.com/User.Read"]
```

### Okta Setup

1. **Create Application:**
   - Okta Admin Console → Applications
   - Type: `Native Application`
   - Grant types: Authorization Code, Device Authorization, Refresh Token

2. **Configure Authorization Server:**
   - Security → API → Authorization Servers
   - Use `default` or create custom

3. **Add Claims:**
   - Groups claim: `groups`
   - Custom claims as needed

4. **Create Groups:**
   - Directory → Groups
   - Create and assign users

**Configuration:**
```yaml
oidc:
  providers:
    - name: "okta-primary"
      issuer: "https://your-domain.okta.com/oauth2/default"
      client_id: "your-okta-client-id"
      client_secret: "your-okta-client-secret"
```

## Security Best Practices

### 1. Encryption Keys

Generate strong encryption keys:
```bash
# Generate 32-byte encryption key
openssl rand -base64 32

# Generate for cloud environments
export TOKEN_ENCRYPTION_KEY=$(openssl rand -base64 32)
```

### 2. File Permissions

Secure configuration files:
```bash
sudo chown root:root /etc/oidc-auth/broker.yaml
sudo chmod 600 /etc/oidc-auth/broker.yaml
sudo chown -R root:root /etc/oidc-auth/
sudo chmod -R 600 /etc/oidc-auth/
```

### 3. Network Security

Configure firewall rules:
```bash
# Allow only necessary ports
sudo ufw allow ssh
sudo ufw allow 443/tcp
sudo ufw enable
```

### 4. TLS Configuration

Use proper SSL/TLS certificates:
```yaml
security:
  tls_verification:
    pin_certificates: true
    trusted_ca_bundle: "/etc/ssl/certs/ca-certificates.crt"
    skip_tls_verify: false
```

### 5. Audit Logging

Enable comprehensive audit logging:
```yaml
audit:
  enabled: true
  format: "json"
  retention_period: "7_years"
  events:
    - "authentication_attempts"
    - "authorization_decisions"
    - "token_validation"
    - "session_management"
    - "policy_violations"
```

## Environment-Specific Configurations

### Development Environment

```yaml
authentication:
  policies:
    development:
      require_groups: ["developers"]
      max_session_duration: "8h"
      allow_untrusted_devices: true
      audit_level: "basic"

security:
  tls_verification:
    skip_tls_verify: true  # Only for development
```

### Staging Environment

```yaml
authentication:
  policies:
    staging:
      require_groups: ["developers", "qa-team"]
      max_session_duration: "4h"
      require_device_trust: true
      audit_level: "standard"
```

### Production Environment

```yaml
authentication:
  policies:
    production:
      require_groups: ["production-access"]
      max_session_duration: "2h"
      require_device_trust: true
      require_additional_mfa: true
      session_recording: true
      audit_level: "detailed"
```

## Troubleshooting

### Common Issues

1. **"Invalid client credentials"**
   - Check client ID and secret
   - Verify client is enabled
   - Check client type (confidential vs public)

2. **"User not in required group"**
   - Verify group membership in OIDC provider
   - Check group claim configuration
   - Verify group mapping

3. **"Token validation failed"**
   - Check token lifetime settings
   - Verify clock synchronization
   - Check issuer URL

4. **"Device flow not supported"**
   - Enable device flow in OIDC provider
   - Check device authorization endpoint
   - Verify grant types

### Debug Configuration

Enable debug logging:
```yaml
server:
  log_level: "debug"

logging:
  level: "debug"
  components:
    auth: "debug"
    policy: "debug"
    security: "debug"
```

### Test Configuration

Test OIDC discovery:
```bash
curl https://your-provider.com/.well-known/openid-configuration
```

Test device flow:
```bash
curl -X POST https://your-provider.com/device/authorize \
  -d "client_id=your-client-id" \
  -d "scope=openid profile email groups"
```

### Log Analysis

Monitor audit logs:
```bash
sudo tail -f /var/log/oidc-auth/audit.log | jq
```

Check service status:
```bash
sudo systemctl status oidc-auth-broker
sudo journalctl -u oidc-auth-broker -f
```

## Migration Guide

### From Version 0.x to 1.x

1. **Backup current configuration:**
   ```bash
   sudo cp /etc/oidc-auth/broker.yaml /etc/oidc-auth/broker.yaml.backup
   ```

2. **Update configuration format:**
   - Review new configuration options
   - Update provider settings
   - Add new security settings

3. **Test configuration:**
   ```bash
   sudo oidc-auth-broker --config /etc/oidc-auth/broker.yaml --validate
   ```

4. **Restart service:**
   ```bash
   sudo systemctl restart oidc-auth-broker
   ```

## Support

For additional support:

- **Documentation:** [GitHub Wiki](https://github.com/scttfrdmn/oidc-pam/wiki)
- **Issues:** [GitHub Issues](https://github.com/scttfrdmn/oidc-pam/issues)
- **Discussions:** [GitHub Discussions](https://github.com/scttfrdmn/oidc-pam/discussions)

## Contributing

To contribute to the configuration templates:

1. Fork the repository
2. Create a feature branch
3. Add your configuration template
4. Update this guide
5. Submit a pull request

Templates should include:
- Complete working configuration
- Setup instructions
- Common issues and solutions
- Testing procedures