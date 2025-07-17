# System Requirements

This document outlines the system requirements for building and running OIDC PAM.

## Build Requirements

### Operating System
- Linux (Ubuntu 18.04+, RHEL 8+, CentOS 8+, Debian 10+)
- macOS 11.0+ (for development)

### Core Dependencies
- Go 1.21 or later
- GCC or Clang compiler
- Make
- Git

### System Libraries

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libpam0g-dev \
    libjson-c-dev \
    pkg-config \
    libsystemd-dev
```

#### RHEL/CentOS/Fedora
```bash
sudo yum install -y \
    gcc \
    make \
    pam-devel \
    json-c-devel \
    pkgconfig \
    systemd-devel

# Or for newer versions:
sudo dnf install -y \
    gcc \
    make \
    pam-devel \
    json-c-devel \
    pkgconfig \
    systemd-devel
```

#### macOS (Development)
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install json-c pkg-config

# Note: PAM is part of macOS but may need additional setup for development
```

### Go Dependencies
All Go dependencies are managed through `go.mod` and will be automatically downloaded during build.

## Runtime Requirements

### System Services
- systemd (for service management)
- PAM (Pluggable Authentication Modules)
- Unix domain sockets support

### Network Requirements
- HTTPS access to OIDC providers
- Network connectivity for device flow authentication
- DNS resolution for OIDC provider endpoints

### File System Requirements
- `/etc/oidc-auth/` directory for configuration
- `/var/run/oidc-auth/` directory for runtime files (sockets, PIDs)
- `/var/log/oidc-auth/` directory for logs (optional)
- `/lib/security/` directory for PAM module
- `/usr/local/bin/` directory for binaries

### User Permissions
- Root privileges required for:
  - Installing PAM module to `/lib/security/`
  - Configuring PAM in `/etc/pam.d/`
  - Installing systemd service files
  - Creating system directories

## Development Requirements

### Additional Tools
- golangci-lint (for linting)
- gosec (for security scanning)
- Docker (for containerized builds)

### IDE/Editor Support
- Go language server (gopls)
- C/C++ language support for PAM module development

## Cloud Provider Requirements

### OIDC Provider Support
- OpenID Connect 1.0 compatible provider
- OAuth 2.0 device authorization grant support
- PKCE (Proof Key for Code Exchange) support (recommended)

### Supported Providers
- Microsoft Azure AD
- Google Workspace
- Okta
- Auth0
- Keycloak
- Any OpenID Connect 1.0 compliant provider

## Security Requirements

### Encryption
- AES-256 encryption for token storage
- TLS 1.2+ for all network communications
- Strong random number generation

### System Security
- SELinux/AppArmor compatibility
- Secure file permissions
- Audit logging capabilities

## Performance Requirements

### Minimum System Resources
- RAM: 512MB available
- CPU: 1 core
- Disk: 100MB for binaries and logs

### Recommended System Resources
- RAM: 2GB available
- CPU: 2 cores
- Disk: 1GB for logs and temporary files

## Testing Requirements

### Unit Testing
- Go test framework
- CGO test support
- Mock OIDC provider for testing

### Integration Testing
- PAM test framework
- systemd service testing
- Network connectivity testing

## Compliance Requirements

### Standards Compliance
- OpenID Connect 1.0
- OAuth 2.0
- RFC 8628 (OAuth 2.0 Device Authorization Grant)
- PAM API compliance

### Audit Requirements
- Comprehensive audit logging
- Syslog integration
- Compliance with security frameworks (SOC 2, ISO 27001)

## Troubleshooting

### Common Issues
1. **Missing libraries**: Ensure all system libraries are installed
2. **Permission errors**: Check file permissions and user privileges
3. **Network connectivity**: Verify HTTPS access to OIDC providers
4. **PAM configuration**: Ensure PAM module is properly configured

### Debug Mode
Enable debug mode for detailed logging:
```bash
export OIDC_DEBUG=true
```

### Log Locations
- System logs: `/var/log/syslog` or `journalctl -u oidc-auth-broker`
- Application logs: `/var/log/oidc-auth/` (if configured)
- PAM logs: `/var/log/auth.log`

## Version Compatibility

### Go Version Support
- Minimum: Go 1.21
- Recommended: Latest stable Go version
- Testing: Go 1.21, 1.22, 1.23+

### System Compatibility
- Ubuntu LTS versions (18.04, 20.04, 22.04, 24.04)
- RHEL/CentOS 8, 9
- Debian 10, 11, 12
- Amazon Linux 2, 2023
- SUSE Linux Enterprise Server 15

For the most up-to-date compatibility information, see the [GitHub Actions CI configuration](.github/workflows/ci.yml).