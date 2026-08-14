# Security Policy

## Supported Versions

We release security patches for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4.0 | :x:                |

**Note:** OIDC PAM is pre-1.0 and under active development. Always test thoroughly before deploying to production, and keep an emergency access path when configuring PAM.

## Reporting a Vulnerability

We take the security of OIDC PAM seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security issues via one of the following methods:

1. **GitHub Security Advisories** (Preferred)
   - Go to https://github.com/scttfrdmn/oidc-pam/security/advisories
   - Click "Report a vulnerability"
   - Fill out the form with details

2. **Email**
   - Send details to: security@scttfrdmn.com (if available)
   - Use subject line: `[SECURITY] OIDC PAM Vulnerability Report`

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential impact and severity assessment
- **Reproduction Steps**: Step-by-step instructions to reproduce the issue
- **Affected Versions**: Which versions are affected
- **Proof of Concept**: Code, screenshots, or logs demonstrating the issue
- **Suggested Fix**: If you have recommendations for fixing the issue

### Response Timeline

- **Initial Response**: Within 48 hours of receiving your report
- **Status Update**: Within 7 days with our assessment and timeline
- **Resolution**: We aim to release patches within 30 days for critical issues

### Disclosure Policy

- We follow **coordinated disclosure**
- We'll work with you to understand and resolve the issue
- We'll publicly disclose the vulnerability after a patch is released
- You'll be credited in the security advisory (unless you prefer to remain anonymous)

## Security Best Practices

When deploying OIDC PAM, follow these security recommendations:

### 1. Authentication & Authorization
- Use strong OIDC providers with MFA enabled
- Implement least-privilege access policies
- Regularly review and rotate credentials
- Enable audit logging for all authentication events

### 2. Configuration Security
- Store configuration files with restricted permissions (600)
- Never commit credentials or secrets to version control
- Use environment variables or secure key management systems
- Validate all OIDC provider certificates

### 3. Network Security
- Use TLS/HTTPS for all OIDC communications
- Restrict broker socket permissions (Unix socket: 700)
- Deploy behind firewalls in production
- Use VPNs or private networks where possible

### 4. System Security
- Keep the system and dependencies up to date
- Run the broker with minimal privileges
- Use SELinux or AppArmor when available
- Monitor system logs for suspicious activity

### 5. PAM Configuration
- Test PAM configurations in non-production first
- Always maintain a backup authentication method
- Use `sufficient` rather than `required` during testing
- Document emergency access procedures

## Security Features

OIDC PAM includes several security features:

- **Encrypted Token Storage**: AES-256-GCM authenticated encryption (base64 32-byte key; no passphrase stretching)
- **Identity Binding**: The authenticated OIDC identity is bound to the requested local username, and `require_groups` is enforced
- **Comprehensive Audit Logging**: All authentication events logged
- **Risk-Based Policy Engine**: Geographic and temporal access controls
- **Automatic Key Rotation**: SSH key lifecycle management
- **Session Management**: Automatic token expiration and cleanup
- **Secure Communication**: Unix socket with strict permissions

## Release Integrity and Provenance

From **v0.5.1** onward, every release artifact is signed and carries build
provenance. There is **no oidc-pam signing key** and none is stored in this
repository or in its secrets: signing is
[cosign](https://docs.sigstore.dev/) *keyless*, so the signer is the release
workflow's own GitHub Actions OIDC identity and the certificate is short-lived.

Each release publishes, for both `amd64` and `arm64`:

- the archive and its `.sha256`
- a cosign signature bundle (`.sigstore.json`) for the archive
- a single signed `SHA256SUMS` manifest covering every architecture
- a **SLSA v1 build provenance attestation** per archive, verifiable with
  `gh attestation verify`

Each archive also carries an internal `SHA256SUMS` of the binaries it installs;
the bundled `install.sh` verifies it and refuses to install on a mismatch.

**Verify before you install.** `pam_oidc.so` is loaded into `sshd` and the broker
runs as root, so the checksum alone — published to the same page as the archive it
describes — is not evidence of origin. The exact
`cosign verify-blob --certificate-identity ... --certificate-oidc-issuer ...` and
`gh attestation verify` commands, what each one proves, and how to verify offline
are in **[docs/verifying-releases.md](docs/verifying-releases.md)**.

Releases up to and including v0.5.0 are unsigned and cannot be signed
retroactively.

## Security Scanning

This project uses automated security scanning:

- **gosec**: Go security vulnerability scanner
- **govulncheck**: Official Go vulnerability database checker
- **CodeQL**: Semantic code analysis (security-extended + security-and-quality)
- **Semgrep**: OWASP Top 10 and CWE Top 25 checks
- **Dependency Review**: Flags vulnerable/denied-license dependencies on PRs
- **OpenSSF Scorecard**: Supply chain security assessment

Security scans run automatically on:
- Every commit to main
- All pull requests
- Weekly scheduled runs

## Known Security Considerations

### Pre-1.0 Release
This is a **pre-1.0 release**. While the codebase has undergone an internal
security audit (all findings remediated as of v0.4.x):
- It has not undergone an independent third-party security audit
- Breaking changes may occur before 1.0
- Validate thoroughly for your own environment before high-security production use

### PAM Integration
- PAM modules run with elevated privileges
- Misconfigurations can lock users out of systems
- Always maintain backup authentication methods
- Test thoroughly in non-production environments first

### OIDC Dependencies
- Security depends on your OIDC provider's security
- Ensure your OIDC provider follows security best practices
- Use providers with strong authentication mechanisms
- Enable audit logging at the provider level

## Security Updates

Security updates will be:
- Released as patch versions (e.g., 0.4.1 → 0.4.2)
- Documented in CHANGELOG.md
- Announced via GitHub Security Advisories
- Tagged with `security` label

## Compliance

OIDC PAM includes features to support compliance with:
- **SOC 2**: Comprehensive audit logging
- **PCI DSS**: Strong authentication and audit trails
- **HIPAA**: Access controls and audit logging
- **GDPR**: User access management and logging

However, **you are responsible** for ensuring your deployment meets compliance requirements for your specific use case.

## Questions?

If you have questions about security but not a vulnerability to report:
- Open a GitHub Discussion
- Review [DEPLOYMENT.md](DEPLOYMENT.md) and [configs/CONFIGURATION-GUIDE.md](configs/CONFIGURATION-GUIDE.md)
- Check the security configuration examples in [`configs/security/`](configs/security/)

## Acknowledgments

We appreciate the security research community and will acknowledge researchers who responsibly disclose vulnerabilities (unless they prefer to remain anonymous).

Thank you for helping keep OIDC PAM and its users secure!
