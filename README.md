# OIDC PAM: Modern Authentication for Linux Systems

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.25-blue)](https://golang.org/)
[![Version](https://img.shields.io/badge/Version-0.4.2-blue)](https://github.com/scttfrdmn/oidc-pam/releases)

A comprehensive Linux authentication solution using OpenID Connect (OIDC) that modernizes SSH, console, and GUI logins with passkey support, automatic SSH key management, and enterprise-grade audit capabilities.

## 🚀 Features

- **Modern Authentication**: Replace SSH keys with OIDC + Passkeys
- **Universal PAM Integration**: Works with SSH, console, and GUI logins
- **Automatic SSH Key Management**: Generate, rotate, and revoke SSH keys automatically
- **Enterprise Identity Integration**: Support for Okta, Azure AD, Auth0, Google Workspace, AWS IAM Identity Center, and any OIDC provider
- **Mobile-First UX**: Authenticate via QR codes and mobile passkeys
- **Strong Authorization**: Binds the OIDC identity to the requested local user and enforces `require_groups`
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

- Go 1.25 or higher
- PAM development libraries
- systemd (for service management)

### Installation

#### From a release (recommended)

Download the latest `linux/amd64` or `linux/arm64` tarball, verify it, and run the
bundled installer. The installer places the binaries, an example config, and the
systemd unit; it does **not** modify PAM unless you pass `--configure-pam`.

```bash
VERSION=v0.4.0
ARCH=amd64   # or arm64

curl -fsSLO https://github.com/scttfrdmn/oidc-pam/releases/download/${VERSION}/oidc-pam-${VERSION}-linux-${ARCH}.tar.gz
curl -fsSLO https://github.com/scttfrdmn/oidc-pam/releases/download/${VERSION}/oidc-pam-${VERSION}-linux-${ARCH}.tar.gz.sha256
sha256sum -c oidc-pam-${VERSION}-linux-${ARCH}.tar.gz.sha256

tar -xzf oidc-pam-${VERSION}-linux-${ARCH}.tar.gz
cd oidc-pam-${VERSION}-linux-${ARCH}
sudo ./install.sh            # add --configure-pam to wire pam_oidc.so into sshd
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for the full deployment guide (including the
identity model and prerequisites).

#### From source

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y golang libpam0g-dev libjson-c-dev build-essential

# RHEL/CentOS/Fedora
sudo dnf install -y golang pam-devel json-c-devel gcc make

git clone https://github.com/scttfrdmn/oidc-pam.git
cd oidc-pam
make build
sudo make install-dev
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
      # Required: the claim whose value must match the local username being
      # logged into. The broker refuses to activate a session if it does not
      # match, preventing an IdP user from logging in as another local account.
      user_mapping:
        username_claim: "preferred_username"

authentication:
  token_lifetime: "8h"
  require_groups: ["linux-users"]    # enforced against the user's OIDC groups

security:
  audit_enabled: true
  # Required: base64-encoded 32-byte key. Generate with `oidc-admin gen-key`.
  token_encryption_key: "REPLACE-with-output-of-oidc-admin-gen-key"
```

> **Security note:** `token_encryption_key` must be a base64-encoded 32-byte key
> (generate with `oidc-admin gen-key`), and `username_claim` must be set — both
> are validated at startup. See [SECURITY.md](SECURITY.md) and
> [configs/CONFIGURATION-GUIDE.md](configs/CONFIGURATION-GUIDE.md).

Providers that do not expose a public `/.well-known/openid-configuration` endpoint (such as AWS IAM Identity Center) can use `skip_discovery: true` to bypass OIDC discovery and supply endpoints directly:

```yaml
oidc:
  providers:
    - name: aws-identity-center
      issuer: "https://oidc.us-east-2.amazonaws.com"
      skip_discovery: true
      device_endpoint: "https://oidc.us-east-2.amazonaws.com/device_authorization"
      token_endpoint:  "https://oidc.us-east-2.amazonaws.com/token"
      userinfo_endpoint: "https://oidc.us-east-2.amazonaws.com/userInfo"
      jwks_uri: "https://oidc.us-east-2.amazonaws.com/.well-known/jwks.json"
      client_id: "env:OIDC_CLIENT_ID"
      client_secret: "env:OIDC_CLIENT_SECRET"
      scopes: [openid, email, profile]
```

See `configs/providers/aws-identity-center.yaml` for a complete example.

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

- [Quick Start](QUICK-START.md)
- [Deployment Guide](DEPLOYMENT.md) — installation, identity model, prerequisites
- [Configuration Guide](configs/CONFIGURATION-GUIDE.md) — provider setup, security best practices, troubleshooting
- [Requirements](REQUIREMENTS.md)
- [Security Policy](SECURITY.md)
- Provider examples: [`configs/providers/`](configs/providers/) (Okta, Azure AD, Keycloak, AWS IAM Identity Center)
- [`docs/design/`](docs/design/) — early design and positioning notes, kept for provenance. Aspirational, unmaintained, and not a description of the current system

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

# End-to-end: real sshd, real PAM stack, real broker, in Docker
make test-e2e
```

`make test-e2e` is the one that exercises the module as PAM sees it — every case
is an actual SSH login. See [test/e2e/README.md](test/e2e/README.md).

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📋 Roadmap

### Delivered (through v0.4.0)
- [x] OIDC device flow with nonce replay protection
- [x] PAM module + helper (CGO) and authentication broker
- [x] SSH key lifecycle management with symlink-safe `authorized_keys` writes
- [x] Multi-provider support (Okta, Azure AD, Keycloak, AWS IAM Identity Center, generic OIDC)
- [x] `skip_discovery` for providers without a public discovery endpoint
- [x] Identity binding (OIDC identity → local username) and `require_groups` enforcement
- [x] Risk-based policy engine and comprehensive audit logging
- [x] Prometheus metrics, multi-arch release artifacts (amd64/arm64)
- [x] Security-audited: AES-256-GCM token encryption, hardened IPC trust boundary

### Planned
- [ ] High availability / multiple broker instances
- [ ] Performance optimization and scale testing
- [ ] Expanded provider and platform test coverage

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

- **Modern Cryptography**: AES-256-GCM token encryption with a base64 32-byte key (`oidc-admin gen-key`); ID token signature, issuer, audience, and nonce all verified
- **Hardened Trust Boundary**: Root-only Unix-socket IPC with `SO_PEERCRED` verification; symlink-safe, `O_NOFOLLOW` `authorized_keys` writes
- **Authorization**: OIDC identity bound to the local username; group membership enforced
- **Audit Logging**: Complete access trails for compliance, with backpressure rather than silent drops
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

**Current Status**: Pre-1.0 (v0.4.0) - Under active development

Core functionality is implemented and the codebase has undergone a full security
audit (all findings remediated). It is not yet recommended for unattended
production use without your own validation. Always test thoroughly in a
non-production environment and keep an emergency access path while configuring PAM.

## 💬 Community

- **Discussions**: [GitHub Discussions](https://github.com/scttfrdmn/oidc-pam/discussions)
- **Issues**: [GitHub Issues](https://github.com/scttfrdmn/oidc-pam/issues)
- **Wiki**: [Project Wiki](https://github.com/scttfrdmn/oidc-pam/wiki)

---

**Built with ❤️ for the open source community**