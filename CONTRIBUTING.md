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

**The shipped module is C only, and nothing in it calls Go.** All six entry
points are in `cgo_bridge_linux.c`; the package's Go files are cgo wrappers that
let `go test` drive that C (cgo is not permitted in `_test.go` files, so they live
in normal ones). `scripts/build-pam-module.sh` therefore compiles the one C file
with the C compiler rather than building the package as a Go `c-shared` library,
which is what keeps the Go runtime — its threads, its handlers for `SIGSEGV`,
`SIGBUS`, `SIGFPE`, `SIGPIPE` and `SIGURG`, and `DF_1_NODELETE` — out of every
`sshd` pre-auth child that loads the module (#198). **A `//export` in this package,
or any other C→Go call, brings all of that back**, so it is a change to weigh
rather than make in passing.

**`scripts/build-pam-module.sh` is the only thing that builds the module.** The
Makefile, both release scripts, the e2e image and the release workflow all call it,
and it applies the hardening flags and inspects what it produced. That inspection
cannot be separated from the build: a module with no entry points in it exits 0,
because a header supplies valid declarations, and that shipped in every release
before #140 was found. `make check-pam-producers`
(`scripts/check-pam-module-producers.sh`) fails the build if a second producer
appears — four producers with the check pasted into one of them is what #222 was.

**The C must stay in `cmd/pam-module`** so `go test` still compiles it: cgo
compiles only the C sources in the directory of the package being built.

Two checks keep that quarantine from eroding: a `macOS (no PAM headers)` CI job
that runs `go build/vet/test ./...` on a host with no PAM headers, and
`make check-cgo` (`scripts/check-cgo-quarantine.sh`), which asserts from the build
graph that `cmd/pam-module` is the only package with cgo files on Linux and that
none has any on macOS. `make check-cgo` needs no headers and runs on any OS, so
run it after touching a `#cgo` line or a build constraint.

The `#cgo CFLAGS`/`LDFLAGS` in `bridge_linux.go` carry the same hardening flags as
`scripts/build-pam-module.sh`, so the C the tests exercise is compiled the way the
shipped module is compiled. Change one and change the other. `_FORTIFY_SOURCE` is
set in `cgo_bridge_linux.c` instead of either, because it has to precede the first
system header, and as a floor rather than an assignment so a distribution asking
for a higher level keeps it.

To exercise the C locally, run the sweep CI runs inside a Linux container:

```bash
make verify-linux
```

That builds `test/docker/Dockerfile.verify` and runs `make check-cgo`,
`go vet ./...`, `go test -race ./...` and `golangci-lint run ./...`, then builds
the module and verifies its entry points. CI covers the same ground in the `Test`,
`PAM (cgo)`, `Lint` and `Build` jobs. `make build-pam` refuses to run off Linux
rather than emitting a module with no C in it.

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
│   ├── ipc/               # Broker IPC server and request validation
│   └── testoidc/          # In-process fake OIDC issuer, for tests
├── test/                  # Test support
│   ├── docker/            # Dockerfile.verify (Linux toolchain for cgo)
│   ├── e2e/               # SSH + PAM harness against a fake issuer, in containers
│   └── scripts/           # Shell-level tests (the installers' PAM editing)
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

Name a test after the invariant it holds, not after the function it calls, and
say what breaks if it fails. `TestAcquireAuth` tells a reader nothing when it goes
red; `TestAnOversizedConcurrencyCapIsStillACap` tells them a configured limit
stopped limiting. That is the convention in this repository — about 500 of its
tests are named that way — and it is why a failing run is readable without
opening the test.

```go
// A concurrency cap larger than an int32 must still be a cap. `int32(n)` wrapped
// it to a negative number, and AcquireAuth reads <= 0 as "limit disabled", so the
// largest values an operator could write in the config were the ones that removed
// the limit entirely (#189).
func TestAnOversizedConcurrencyCapIsStillACap(t *testing.T) {
    for _, configured := range []int{math.MaxInt32 + 1, math.MaxInt64} {
        rl := NewRateLimiter(0, configured)
        if rl.maxConcurrentAuths <= 0 {
            t.Errorf("max_concurrent_auths=%d became %d, which AcquireAuth treats as no limit at all",
                configured, rl.maxConcurrentAuths)
        }
        rl.Stop()
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
version strings and the CHANGELOG in sync with the tag automatically. It runs in
two phases, with a pull request in between:

```bash
# 1. Land all changes for the release on main, with entries under
#    "## [Unreleased]" in CHANGELOG.md.

# 2. From a clean checkout of main — stamps the docs and opens the release PR:
scripts/release.sh 0.4.2        # leading 'v' optional

# 3. Wait for the checks, then rebase-merge that PR.

# 4. From a fresh main — tags the merged release commit and pushes the tag:
git checkout main && git pull
scripts/release.sh --tag 0.4.2
```

Phase 1 stamps the README version badge, the `VERSION=v0.4.2` download snippet,
the roadmap heading and the status line, rolls `## [Unreleased]` into a dated
`## [0.4.2]` section, commits `chore(release): v0.4.2` on `release/v0.4.2`, and
opens the pull request. Phase 2 checks that `main` really does carry that commit
— badge, snippet, CHANGELOG heading and commit subject — then creates the
annotated tag and pushes it.

Pushing the tag is what triggers the Release workflow, which re-verifies that the
tag, the four README strings and the CHANGELOG agree, runs the full CI suite, and
only then builds, signs and publishes the artifacts. A manual tag whose docs are
out of sync fails that check.

**Why two phases.** `main` enforces its required checks on admins too
(`scripts/repo-settings.sh`), so the release commit cannot be pushed straight to
it — it goes through a pull request like every other change. That is the point:
the old single-phase flow published releases from a commit no test had ever run
against. And because this repository rebase-merges, the merge rewrites the
commit: a tag created before the merge would point at a commit that is not on
`main`, so the release would be built and signed from something no branch
contains. Hence the tag waits for phase 2.

### Release Checklist

- [ ] All changes merged to `main` with entries under `## [Unreleased]`
- [ ] All tests pass on `main`
- [ ] `scripts/release.sh <version>` run (stamps README + CHANGELOG, opens the PR)
- [ ] Release PR checks green, **rebase**-merged, `main` pulled
- [ ] `scripts/release.sh --tag <version>` run (tags the merged commit, pushes)
- [ ] Release workflow green; GitHub release and artifacts published

### Repository settings

The protections on `main` and on `v*` tags are recorded in
`scripts/repo-settings.sh` — what they are and why each one is there:

```bash
scripts/repo-settings.sh show     # what GitHub has right now
scripts/repo-settings.sh apply    # make GitHub match the script (idempotent)
```

They live in GitHub's database rather than in the tree, which means nothing
otherwise records them, an admin can widen them without leaving a trace, and a
fork or a restored repository comes up with none of them. Change them by editing
that script and running `apply`, not through the web UI — otherwise the file
stops being true, which is worse than not having it.

In short: `main` takes no direct pushes and requires every CI and security job,
including of admins; `v*` tags cannot be created, moved or deleted by anyone
below admin, because pushing one publishes signed artifacts.

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