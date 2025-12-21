# Security Policy

## Supported Versions

We release security patches for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

**Note:** OIDC PAM is currently in alpha. We strongly recommend thorough testing before deploying to production environments.

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

- **Encrypted Token Storage**: AES-256 encryption for stored tokens
- **Comprehensive Audit Logging**: All authentication events logged
- **Risk-Based Policy Engine**: Geographic and temporal access controls
- **Automatic Key Rotation**: SSH key lifecycle management
- **Session Management**: Automatic token expiration and cleanup
- **Secure Communication**: Unix socket with strict permissions

## Security Scanning

This project uses automated security scanning:

- **gosec**: Go security vulnerability scanner
- **govulncheck**: Official Go vulnerability database checker
- **CodeQL**: Semantic code analysis
- **Trivy**: Container and dependency scanner
- **Semgrep**: OWASP Top 10 and CWE Top 25 checks
- **TruffleHog**: Secret detection
- **OpenSSF Scorecard**: Supply chain security assessment

Security scans run automatically on:
- Every commit to main
- All pull requests
- Weekly scheduled runs

## Known Security Considerations

### Alpha Release
This is an **alpha release**. While we follow security best practices:
- The code has not undergone independent security audit
- Breaking changes may occur in future versions
- Not recommended for high-security production environments without thorough testing

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
- Released as patch versions (e.g., 0.1.0 → 0.1.1)
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
- Review existing documentation in `/docs/`
- Check the security configuration examples in `/configs/security/`

## Acknowledgments

We appreciate the security research community and will acknowledge researchers who responsibly disclose vulnerabilities (unless they prefer to remain anonymous).

Thank you for helping keep OIDC PAM and its users secure!
