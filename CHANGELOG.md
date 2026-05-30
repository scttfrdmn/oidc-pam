# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- DEPLOYMENT.md: "Identity vs. Authentication" guidance explaining that oidc-pam is an authentication layer (use SSSD/a directory for NSS identity and consistent cluster UIDs), why no `libnss_oidc.so` module is shipped, and the provision-on-first-login pattern for directory-less environments

## [0.3.3] - 2026-05-30

### Added
- Release tarballs now bundle an `install.sh` entrypoint (from `scripts/install-release.sh`) that installs prebuilt binaries, the example config, and the systemd unit; PAM is left untouched unless `--configure-pam` is passed

### Changed
- DEPLOYMENT.md: documented the integration model & scope (PAM-only, no NSS module, local accounts must pre-exist, username flows in rather than being resolved out), and corrected the binary-install instructions to match real release asset names

### Fixed
- Flaky `TestServerConcurrentConnections` IPC test that intermittently failed CI with the same "broken pipe" rejection race previously fixed for the malformed-JSON and empty-data tests

## [0.3.2] - 2026-05-30

### Changed
- Dependency updates: x/crypto 0.52.0, x/sys 0.45.0, golangci-lint-action 9.2.1, upload-artifact v7, download-artifact v8

### Fixed
- Flaky IPC connection tests (`TestServerConnectionWithMalformedJSON`, `TestServerConnectionWithEmptyData`) that intermittently failed CI with a "broken pipe" race when the server rejected the non-root test client

## [0.3.1] - 2026-05-19

### Added
- `skip_discovery` provider option for OIDC providers without a public `/.well-known/openid-configuration` endpoint (e.g. AWS IAM Identity Center)
- `jwks_uri` provider field for use with `skip_discovery: true`
- `configs/providers/aws-identity-center.yaml` reference configuration
- AWS IAM Identity Center setup guide in `configs/CONFIGURATION-GUIDE.md`

## [0.3.0] - 2026-05-19

### Added
- Release workflow producing linux/amd64 and linux/arm64 artifacts on tag push

### Changed
- Upgraded to Go 1.25.10 and golangci-lint v2.12.2
- Upgraded gosec to v2.26.1 for Go 1.25 compatibility
- Unpinned govulncheck to track latest releases
- Dependency updates: zerolog 1.35.1, go-jose 4.1.4, setup-go 6.4.0, scorecard-action 2.4.3, dependency-review-action 5.0.0

### Security
- Resolved 7 Go standard library vulnerabilities by upgrading to Go 1.25.10:
  - GO-2026-4971: net.Dial panic with NUL byte
  - GO-2026-4947/4946: crypto/x509 chain building issues
  - GO-2026-4918: net/http HTTP/2 infinite loop
  - GO-2026-4870: crypto/tls unauthenticated KeyUpdate DoS
  - GO-2026-4602: os.FileInfo Root escape
  - GO-2026-4601: net/url incorrect IPv6 parsing

## [0.1.0-alpha.2] - 2025-01-17

### Added
- Complete authentication broker implementation
- OIDC device flow with OAuth2 device authorization grant
- Multi-provider OIDC support (Okta, Azure AD, Auth0, Google Workspace, etc.)
- Session management with automatic expiration and cleanup
- Token manager with encryption and lifecycle management
- Risk-based policy engine with geographic and time-based controls
- Comprehensive audit logging system with multiple outputs
- QR code generation for mobile authentication
- Unix socket IPC server for PAM module communication
- Example configuration files and systemd service
- Security utilities (encryption, audit logging)

### Changed
- Enhanced configuration system with cloud provider auto-discovery
- Improved error handling and logging throughout
- Better separation of concerns in codebase architecture

### Security
- AES-256 encryption for token storage
- Comprehensive audit trails for compliance
- Risk assessment and policy enforcement
- Device trust validation
- Network-based access controls

## [0.1.0-alpha] - 2025-01-17

### Added
- Initial project structure and documentation
- MIT License with proper copyright
- Contributing guidelines and GitHub templates
- Go module structure with dependencies
- Build system with Makefile
- Basic project foundation

---

## Release Notes

### Version 0.1.0-alpha - Initial Release

This is the initial alpha release of OIDC PAM. The project is in early development and is not yet recommended for production use.

**Key Features:**
- Modern authentication using OIDC and passkeys
- Automatic SSH key management
- Cross-platform PAM integration
- Basic audit logging
- Cloud-native configuration

**Known Limitations:**
- Limited testing in production environments
- Basic policy engine
- Limited OIDC provider testing
- No high availability features yet

**Next Steps:**
- Expand OIDC provider support
- Implement advanced policy engine
- Add comprehensive audit trails
- Performance optimization
- Production readiness features

**Breaking Changes:**
- None (initial release)

**Migration Notes:**
- None (initial release)

---

For the complete list of changes, see the [commit history](https://github.com/scttfrdmn/oidc-pam/commits/main).

For upgrade instructions, see the [Installation Guide](docs/installation.md).