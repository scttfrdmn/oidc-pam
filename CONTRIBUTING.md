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

- Go 1.25 or higher
- PAM development libraries (`libpam0g-dev libjson-c-dev`, or `pam-devel json-c-devel`)
- systemd (for service management)
- Docker (for integration tests, and for `make verify-linux` on macOS)

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

The linter set is declared in `.golangci.yml` and the golangci-lint version is
pinned in `.golangci-version`, so a local run matches CI. `make lint` warns if
your installed version differs from the pin — install that version, or use
`make verify-linux`, which always uses it.

### Working on the PAM module

`cmd/pam-module` is the only cgo package. It holds the C bridge
(`cgo_bridge_linux.c`) that implements the six `pam_sm_*` entry points libpam
calls, and it needs `<security/pam_ext.h>` and `<json-c/json.h>`, which macOS does
not have. Its cgo is behind a `//go:build linux` tag, so `go build ./...` and
`go test ./...` work on a Mac — the C and the tests that drive it are simply
absent there. Everything else, `pkg/pam` included, is pure Go.

**The C must stay in `cmd/pam-module`.** cgo compiles only the C sources in the
directory of the package being built, so C living anywhere else is not compiled
into the module — and because a header supplies valid declarations, the build
still exits 0 and produces a `.so` with no entry points in it. That shipped in
every release before this one (#140). `scripts/verify-pam-module.sh` checks the
built artifact for exactly that, and runs from `make build-pam`,
`make verify-linux` and the release workflow.

To exercise the C locally, run the sweep CI runs inside a Linux container:

```bash
make verify-linux
```

That builds `test/docker/Dockerfile.verify` and runs `go vet ./...`,
`go test -race ./pkg/... ./internal/... ./cmd/...` and `golangci-lint run ./...`,
then builds the module and verifies its entry points. CI covers the same ground in
the `PAM (cgo)`, `Lint` and `Build` jobs. `make build-pam` refuses to run off
Linux rather than emitting a module with no C in it.

### Project Structure

```
oidc-pam/
├── cmd/                   # Main applications
│   ├── broker/            # Authentication broker daemon
│   ├── pam-module/        # pam_oidc.so — the C bridge and its cgo wrappers
│   ├── pam-helper/        # PAM helper binary (pam_exec-style integrations)
│   └── oidc-admin/        # Administrative CLI tool
├── pkg/                   # Library code
│   ├── auth/              # Core authentication logic, providers, policy
│   ├── config/            # Configuration management
│   ├── metrics/           # Metrics collection
│   ├── pam/               # PAM result codes and the module's Go-side helpers
│   ├── security/          # Security utilities
│   └── ssh/               # authorized_keys and SSH key management
├── internal/              # Private application code
│   ├── adminapi/          # Admin request/response shapes
│   ├── brokerclient/      # Broker IPC client and device-flow completion
│   └── ipc/               # Broker IPC server and request validation
├── test/                  # Test support
│   ├── config/            # Test configuration
│   ├── docker/            # Dockerfile.verify (Linux toolchain for cgo)
│   ├── integration/       # Integration tests
│   └── keycloak/          # Keycloak realm for manual end-to-end runs
├── docs/                  # Documentation (docs/design/ is unmaintained; see its index)
├── scripts/               # Build, install and verification scripts
└── configs/               # Configuration examples
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

### Cutting a release

Use the release script — it is the single source of truth and keeps the README
version badge and CHANGELOG in sync with the tag automatically:

```bash
# 1. Land all changes for the release on main, with entries under
#    "## [Unreleased]" in CHANGELOG.md.
# 2. From a clean checkout of main:
scripts/release.sh 0.4.2        # leading 'v' optional
```

The script stamps the README badge, rolls `## [Unreleased]` into a dated
`## [0.4.2]` section, commits `chore(release): v0.4.2`, creates the annotated tag,
and (after confirmation) pushes both. Pushing the tag triggers the Release
workflow, which **verifies** the tag, README badge, and CHANGELOG agree before
building and publishing multi-arch artifacts. A manual tag whose docs are out of
sync will fail that check.

### Release Checklist

- [ ] All changes merged to `main` with entries under `## [Unreleased]`
- [ ] All tests pass on `main`
- [ ] `scripts/release.sh <version>` run (stamps README + CHANGELOG, tags, pushes)
- [ ] Release workflow green; GitHub release and artifacts published

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