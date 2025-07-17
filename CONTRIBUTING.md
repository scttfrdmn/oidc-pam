# Contributing to OIDC PAM

Thank you for your interest in contributing to OIDC PAM! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the [existing issues](https://github.com/scttfrdmn/oidc-pam/issues) to avoid duplicates.

**Bug Report Template:**
- Use a clear and descriptive title
- Describe the exact steps to reproduce the problem
- Describe the behavior you observed and what you expected
- Include relevant logs, screenshots, or error messages
- Specify your environment (OS, Go version, etc.)

### Suggesting Enhancements

Enhancement suggestions are welcome! Please:
- Use a clear and descriptive title
- Provide a detailed description of the proposed feature
- Explain why this enhancement would be useful
- Consider the scope and complexity of the change

### Pull Requests

#### Before Submitting

1. **Check existing PRs** to avoid duplicates
2. **Create an issue** for significant changes to discuss the approach
3. **Follow the coding standards** outlined below
4. **Test your changes** thoroughly

#### Pull Request Process

1. **Fork the repository** and create a feature branch from `main`
2. **Make your changes** following the coding standards
3. **Add tests** for new functionality
4. **Update documentation** as needed
5. **Ensure all tests pass**
6. **Submit your pull request**

#### Pull Request Template

- **Description**: What does this PR do?
- **Related Issue**: Link to the related issue (if applicable)
- **Type of Change**: Bug fix, new feature, documentation, etc.
- **Testing**: How has this been tested?
- **Checklist**: 
  - [ ] Code follows the project's style guidelines
  - [ ] Self-review completed
  - [ ] Tests added/updated
  - [ ] Documentation updated
  - [ ] Changelog updated

## Development Setup

### Prerequisites

- Go 1.21 or higher
- PAM development libraries
- systemd (for service management)
- Docker (for integration tests)

### Local Development

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/oidc-pam.git
cd oidc-pam

# Set up upstream remote
git remote add upstream https://github.com/scttfrdmn/oidc-pam.git

# Install dependencies
go mod download

# Build the project
make build

# Run tests
make test

# Run linter
make lint

# Install development version
sudo make install-dev
```

### Project Structure

```
oidc-pam/
├── cmd/                    # Main applications
│   ├── broker/            # Authentication broker daemon
│   ├── pam-helper/        # PAM helper binary
│   └── oidc-admin/        # Administrative CLI tool
├── pkg/                   # Library code
│   ├── auth/             # Core authentication logic
│   ├── config/           # Configuration management
│   ├── display/          # User interface components
│   ├── pam/              # PAM integration
│   ├── security/         # Security utilities
│   └── cloud/            # Cloud provider integrations
├── internal/             # Private application code
│   ├── ipc/             # Inter-process communication
│   └── utils/           # Utility functions
├── test/                 # Test files
│   ├── integration/     # Integration tests
│   └── unit/            # Unit tests
├── docs/                 # Documentation
├── scripts/             # Build and deployment scripts
└── configs/             # Configuration examples
```

## Coding Standards

### Go Style Guide

- Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` to format code
- Use `golint` and `go vet` for static analysis
- Write clear, concise comments
- Use meaningful variable and function names

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(auth): add support for custom OIDC scopes

fix(pam): resolve memory leak in token cache

docs(readme): update installation instructions

test(integration): add end-to-end authentication tests
```

### Testing

#### Unit Tests

- Write unit tests for all public functions
- Use table-driven tests when appropriate
- Mock external dependencies
- Aim for high test coverage

```go
func TestTokenManager_ValidateToken(t *testing.T) {
    tests := []struct {
        name    string
        token   string
        want    bool
        wantErr bool
    }{
        {
            name:    "valid token",
            token:   "valid.jwt.token",
            want:    true,
            wantErr: false,
        },
        // ... more test cases
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

#### Integration Tests

- Test real-world scenarios
- Use Docker containers for external dependencies
- Test error conditions and edge cases
- Include performance tests for critical paths

### Documentation

- Update README.md for user-facing changes
- Add godoc comments for public functions
- Update CHANGELOG.md following Keep a Changelog format
- Include examples in documentation

### Security

- Follow security best practices
- Never commit secrets or credentials
- Use secure coding practices
- Report security issues privately

## Release Process

### Versioning

This project follows [Semantic Versioning](https://semver.org/) (SemVer):

- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Types

- **Alpha**: Early development releases (0.x.x-alpha.x)
- **Beta**: Feature-complete releases (0.x.x-beta.x)
- **Release Candidate**: Production-ready candidates (0.x.x-rc.x)
- **Stable**: Production releases (x.x.x)

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in relevant files
- [ ] Git tag created
- [ ] GitHub release created
- [ ] Artifacts built and published

## Community

### Communication

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Pull Requests**: Code contributions and reviews

### Getting Help

- Check the [documentation](docs/)
- Search [existing issues](https://github.com/scttfrdmn/oidc-pam/issues)
- Ask questions in [GitHub Discussions](https://github.com/scttfrdmn/oidc-pam/discussions)

## Recognition

Contributors are recognized in:
- GitHub contributors list
- Release notes for significant contributions
- Project documentation

## Legal

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

## Questions?

If you have questions about contributing, please:
1. Check this document first
2. Search existing issues and discussions
3. Create a new discussion or issue

Thank you for contributing to OIDC PAM! 🚀