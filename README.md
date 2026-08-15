# OIDC PAM: Modern Authentication for Linux Systems

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.25-blue)](https://golang.org/)
[![Version](https://img.shields.io/badge/Version-0.5.1-blue)](https://github.com/scttfrdmn/oidc-pam/releases)

A comprehensive Linux authentication solution using OpenID Connect (OIDC) that modernizes SSH login — and any other interactive PAM service you wire it into — with passkey support, automatic SSH key management, and enterprise-grade audit capabilities.

## 🚀 Features

- **Modern Authentication**: Replace SSH keys with OIDC + Passkeys
- **PAM Integration**: SSH is tested end-to-end; `configs/pam/` also carries example stacks for console `login`, `su` and `sudo`. Not for display managers, and never for the host-wide `common-auth`/`system-auth` stack — a device flow needs a terminal and a user in front of it
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
│    SSH • Console • su/sudo • Automatic Key Provisioning   │
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
VERSION=v0.5.1
ARCH=amd64   # or arm64

curl -fsSLO https://github.com/scttfrdmn/oidc-pam/releases/download/${VERSION}/oidc-pam-${VERSION}-linux-${ARCH}.tar.gz
curl -fsSLO https://github.com/scttfrdmn/oidc-pam/releases/download/${VERSION}/oidc-pam-${VERSION}-linux-${ARCH}.tar.gz.sha256
sha256sum -c oidc-pam-${VERSION}-linux-${ARCH}.tar.gz.sha256

tar -xzf oidc-pam-${VERSION}-linux-${ARCH}.tar.gz
cd oidc-pam-${VERSION}-linux-${ARCH}
sudo ./install.sh            # add --configure-pam to wire pam_oidc.so into sshd
```

Releases from v0.5.1 on are signed with cosign keyless signing and carry SLSA
build provenance. The checksum above only detects a corrupted download — to check
that the tarball came from this repository's release workflow, verify the signature
and the attestation:

```bash
cosign verify-blob \
  --bundle oidc-pam-${VERSION}-linux-${ARCH}.tar.gz.sigstore.json \
  --certificate-identity "https://github.com/scttfrdmn/oidc-pam/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  oidc-pam-${VERSION}-linux-${ARCH}.tar.gz

gh attestation verify oidc-pam-${VERSION}-linux-${ARCH}.tar.gz \
  --repo scttfrdmn/oidc-pam \
  --signer-workflow scttfrdmn/oidc-pam/.github/workflows/release.yml \
  --source-ref refs/tags/${VERSION}
```

Both must succeed before you install. See
[docs/verifying-releases.md](docs/verifying-releases.md) for what each check
proves, the signed `SHA256SUMS` manifest, and offline verification.

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
        # If that claim is an email or a UPN, the whole value must equal the local
        # username by default. To let the local part match instead — alice@example.com
        # logging in as "alice" — opt in and pin the domains it may come from:
        # username_claim_strip_domain: true
        # allowed_email_domains: ["example.com"]

authentication:
  token_lifetime: "8h"
  require_groups: ["linux-users"]    # enforced against the user's OIDC groups
  # No OIDC identity may log in as uid 0 or any account with uid < 1000. List an
  # account here to make a deliberate exception:
  # allow_privileged_accounts: ["deploy"]

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
```

Every login runs the device flow. `pam_oidc.so` sends no session ID with its
authentication request, so the broker has nothing to match a login against and
starts a new flow each time; the SSH key it provisions belongs to that session.
There is no cached credential that lets the next `ssh` skip the prompt.

## 📚 Documentation

- [Quick Start](QUICK-START.md)
- [Deployment Guide](DEPLOYMENT.md) — installation, identity model, prerequisites
- [Configuration Guide](configs/CONFIGURATION-GUIDE.md) — provider setup, security best practices, troubleshooting
- [Requirements](REQUIREMENTS.md)
- [Security Policy](SECURITY.md)
- [Verifying a Release](docs/verifying-releases.md) — cosign signature and SLSA provenance checks for release artifacts
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

### Delivered (through v0.5.1)
- [x] OIDC device flow with nonce replay protection
- [x] PAM module + helper (CGO) and authentication broker
- [x] SSH key lifecycle management with symlink-safe `authorized_keys` writes
- [x] Multi-provider support (Okta, Azure AD, Keycloak, AWS IAM Identity Center, generic OIDC)
- [x] `skip_discovery` for providers without a public discovery endpoint
- [x] Identity binding (OIDC identity → local username) and `require_groups` enforcement
- [x] Risk-based policy engine and comprehensive audit logging
- [x] Prometheus metrics, multi-arch release artifacts (amd64/arm64)
- [x] Security-audited: AES-256-GCM token encryption, hardened IPC trust boundary
- [x] Home directories resolved from the account database through NSS, never derived from the login name
- [x] Key lifetime enforced by sshd itself via `expiry-time=`, so it holds whether or not the broker is running
- [x] End-to-end suite in CI: real sshd, real PAM stack, real broker, every case an actual SSH login

### Planned
- [ ] High availability / multiple broker instances
- [ ] Performance optimization and scale testing
- [ ] Expanded provider and platform test coverage

## 📊 Supported Platforms

| Platform | OpenSSH | SSH (`sshd`) | Console (`login`), `su`, `sudo` | Display manager |
|----------|---------|--------------|---------------------------------|-----------------|
| Debian 12 (bookworm) | 9.2p1 | ✅ Tested in CI | Example config, untested | Not supported |
| Debian 11, Ubuntu 20.04+, Ubuntu 22.04+ | 8.4p1 / 8.2p1 / 8.9p1 | Expected to work | Example config, untested | Not supported |
| RHEL 8+, CentOS Stream 8+, Fedora 35+ | 8.0p1 / 8.0p1 / 8.7p1+ | Expected to work | Example config, untested | Not supported |
| Amazon Linux 2, RHEL/CentOS 7 | 7.4p1 | ❌ Not supported | Not supported | Not supported |

**Requires OpenSSH 7.7 or newer.** The broker writes each login's key with an
`expiry-time="…"` option so that sshd, not the broker, enforces the key's lifetime.
That option was added in OpenSSH 7.7, and an sshd that does not recognise an
authorized_keys option refuses the whole entry — so on an older sshd every key the
broker installs is rejected and the account is authenticated and then cannot log
in. The version column above is what each platform ships; check anything not listed
with `ssh -V`. Nothing detects this for you yet
([#199](https://github.com/scttfrdmn/oidc-pam/issues/199)).

**Tested in CI** means `test/e2e` performs real SSH logins against the built
`pam_oidc.so` on that image, with the stack `configs/pam/ssh` ships. That harness
runs on Debian 12 and covers `sshd` and nothing else.

**Expected to work** means the module builds against that distribution's libpam and
json-c, the platform's sshd is new enough for the `expiry-time=` option above, and
nothing else about it is known to differ — not that a login has been run on it.

**Example config, untested** means `configs/pam/` carries a stack for the service
but nobody has verified that its PAM conversation displays the verification URL.
Deploy those one service at a time, from a host you can still get back into, and
never by way of `common-auth`/`system-auth` — see
[configs/pam/README.md](configs/pam/README.md).

**Not supported**: no `gdm`/`sddm`/`lightdm` stack is shipped. The module shows
the device-flow instructions with `PAM_TEXT_INFO`, which a graphical greeter would
render as a block of ASCII art if it shows it at all.

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

**Current Status**: Pre-1.0 (v0.5.1) - Under active development

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