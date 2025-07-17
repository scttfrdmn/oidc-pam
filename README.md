# OIDC PAM: Modern Authentication for Linux Systems

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.21-blue)](https://golang.org/)
[![Version](https://img.shields.io/badge/Version-0.1.0--alpha-red)](https://github.com/scttfrdmn/oidc-pam/releases)

A comprehensive Linux authentication solution using OpenID Connect (OIDC) that modernizes SSH, console, and GUI logins with passkey support, automatic SSH key management, and enterprise-grade audit capabilities.

## 🚀 Features

- **Modern Authentication**: Replace SSH keys with OIDC + Passkeys
- **Universal PAM Integration**: Works with SSH, console, and GUI logins
- **Automatic SSH Key Management**: Generate, rotate, and revoke SSH keys automatically
- **Enterprise Identity Integration**: Support for Okta, Azure AD, Auth0, Google Workspace, and any OIDC provider
- **Mobile-First UX**: Authenticate via QR codes and mobile passkeys
- **Comprehensive Audit**: Complete access trails for compliance (SOC 2, PCI, HIPAA)
- **Cloud-Native**: Auto-configuration for AWS, Azure, and GCP
- **Research Computing**: Special features for academic and scientific computing

## 🎯 Problem It Solves

Traditional SSH key management is broken:
- **Key Sprawl**: Thousands of orphaned keys across infrastructure
- **No Rotation**: Keys created years ago still granting access
- **No Audit Trail**: No visibility into who has access to what
- **Poor UX**: Manual key distribution and management
- **Security Gaps**: No MFA, no real-time revocation

OIDC PAM provides a modern, secure, and user-friendly alternative.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    OIDC Provider Layer                     │
│     Okta/Azure AD/Auth0 + Passkeys + MFA + Groups         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Authentication Broker Layer                 │
│  • Device Flow Orchestration • Token Management            │
│  • SSH Key Lifecycle Mgmt   • Multi-Provider Support      │
│  • Audit Logging           • Cloud Integration             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     PAM Integration Layer                   │
│    SSH • Console • GUI • Automatic Key Provisioning       │
└─────────────────────────────────────────────────────────────┘
```

## 🚦 Quick Start

### Prerequisites

- Go 1.21 or higher
- PAM development libraries
- systemd (for service management)

### Installation

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y golang libpam0g-dev build-essential

# One-line installation
curl -sSL https://raw.githubusercontent.com/scttfrdmn/oidc-pam/main/scripts/install.sh | \
  OIDC_PROVIDER="https://your-provider.com" \
  OIDC_CLIENT_ID="your-client-id" \
  bash
```

#### RHEL/CentOS/Fedora
```bash
sudo dnf install -y golang pam-devel gcc make

# One-line installation
curl -sSL https://raw.githubusercontent.com/scttfrdmn/oidc-pam/main/scripts/install.sh | \
  OIDC_PROVIDER="https://your-provider.com" \
  OIDC_CLIENT_ID="your-client-id" \
  bash
```

### Configuration

```yaml
# /etc/oidc-auth/broker.yaml
oidc:
  providers:
    - name: "company"
      issuer: "https://company.okta.com"
      client_id: "your-client-id"
      scopes: ["openid", "email", "groups"]

authentication:
  token_lifetime: "8h"
  require_groups: ["linux-users"]
  
security:
  audit_enabled: true
```

### Usage

```bash
# SSH with OIDC authentication
ssh user@server.company.com

# First-time authentication flow:
# 1. QR code displayed or device URL provided
# 2. User scans QR code or visits URL on mobile device
# 3. Authenticates with passkey (Face ID/Touch ID)
# 4. SSH key automatically provisioned
# 5. SSH session established

# Subsequent access uses cached SSH key
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [OIDC Provider Setup](docs/providers.md)
- [Cloud Deployment](docs/cloud-deployment.md)
- [Research Computing](docs/research-computing.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🔧 Development

### Build from Source

```bash
git clone https://github.com/scttfrdmn/oidc-pam.git
cd oidc-pam

# Build all components
make build

# Run tests
make test

# Install development version
sudo make install-dev
```

### Testing

```bash
# Unit tests
make test

# Integration tests
make test-integration

# End-to-end tests
make test-e2e
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Development Setup](docs/development/setup.md)
- [Architecture Overview](docs/development/architecture.md)

## 📋 Roadmap

### v0.1.0 (Alpha) - Foundation
- [x] Basic OIDC Device Flow implementation
- [x] Core PAM module
- [x] SSH key lifecycle management
- [ ] Basic audit logging
- [ ] Installation scripts

### v0.2.0 (Beta) - Enterprise Features
- [ ] Multi-provider support
- [ ] Cloud metadata integration
- [ ] Advanced policy engine
- [ ] Comprehensive audit trails

### v1.0.0 (GA) - Production Ready
- [ ] High availability
- [ ] Performance optimization
- [ ] Complete documentation
- [ ] Enterprise certifications

## 📊 Supported Platforms

| Platform | SSH | Console | GUI | Status |
|----------|-----|---------|-----|--------|
| Ubuntu 22.04+ | ✅ | ✅ | ✅ | Stable |
| Ubuntu 20.04+ | ✅ | ✅ | ✅ | Stable |
| RHEL 8+ | ✅ | ✅ | ✅ | Stable |
| CentOS 8+ | ✅ | ✅ | ✅ | Stable |
| Fedora 35+ | ✅ | ✅ | ✅ | Stable |
| Debian 11+ | ✅ | ✅ | ✅ | Beta |

## 🛡️ Security

- **Modern Cryptography**: Uses current OIDC and OAuth2 standards
- **Secure Token Storage**: Encrypted tokens with secure key management
- **Audit Logging**: Complete access trails for compliance
- **Zero Trust**: No implicit trust, every access verified

For security issues, please see our [Security Policy](SECURITY.md).

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- The [OpenID Connect](https://openid.net/connect/) specification
- The [OAuth2 Device Flow](https://tools.ietf.org/html/rfc8628) RFC
- The [Linux PAM](http://www.linux-pam.org/) project
- The research computing community for guidance and feedback

## 📈 Status

**Current Status**: Alpha - Under active development

This project is in early development. While functional, it's not yet recommended for production use. Please test thoroughly in non-production environments.

## 💬 Community

- **Discussions**: [GitHub Discussions](https://github.com/scttfrdmn/oidc-pam/discussions)
- **Issues**: [GitHub Issues](https://github.com/scttfrdmn/oidc-pam/issues)
- **Wiki**: [Project Wiki](https://github.com/scttfrdmn/oidc-pam/wiki)

---

**Built with ❤️ for the open source community**