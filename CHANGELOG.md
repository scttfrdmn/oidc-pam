# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Complete PAM module implementation with CGO bridge
- SSH key lifecycle management and authorized_keys integration
- PAM helper binary for command-line authentication
- Comprehensive test framework for PAM and SSH components
- System requirements documentation (REQUIREMENTS.md)
- Support for json-c library integration
- Admin CLI tool for system management and monitoring
- Advanced risk-based policy engine with multi-factor assessment
- Real-time health monitoring and diagnostics
- Dynamic MFA requirements based on risk scoring
- Adaptive session duration based on risk levels
- Comprehensive integration tests for all system components
- Benchmark tests for performance validation
- End-to-end testing infrastructure

### Changed
- Enhanced build system with proper PAM module compilation
- Improved CGO integration with system libraries
- Updated Makefile for cross-platform builds
- Enhanced policy engine with configurable risk weights
- Improved security controls with behavioral analysis
- Modernized codebase by replacing deprecated io/ioutil functions
- Enhanced error handling and code quality across modules

### Fixed
- CGO compilation issues with variadic functions
- Build dependencies for macOS and Linux
- Test framework timestamp precision issues
- Risk assessment algorithm accuracy and performance
- Integration test configuration and compilation issues
- Linting issues including unused functions and imports
- Error handling in network connections and file operations

### Security
- Secure PAM module implementation with proper logging
- Enhanced SSH key management with expiration handling
- Multi-factor risk assessment (geographic, temporal, device, behavioral, network)
- Business hours and trusted network validation
- Comprehensive audit trails for risk-based decisions

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