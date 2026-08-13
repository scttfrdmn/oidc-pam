# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Critical (#121): the Go client path also treated device-flow initiation as
  authentication success.** `PAMModule.AuthenticateUser` returned nil as soon as
  the broker replied `success: true`, which it does the moment it *starts* the
  device flow, and `oidc-pam-helper` exited 0 on that — so `pam_exec`-style
  integrations granted the login before the user had proved anything, exactly as
  the C module did (#120). It now waits for the flow to complete and returns
  `*PAMAuthFailure` on refusal and on an exhausted timeout.
- **(#121)** New `internal/brokerclient`: the broker IPC protocol and the
  device-flow completion logic in one **pure-Go, cgo-free** package, so the
  wait/poll/deny behaviour is covered by `go test` on every platform rather than
  living only in C that a developer laptop cannot compile. It dials per request
  (the broker serves one request per connection), polls `check_session` with
  `user_id`, honours `metadata.polling_interval` clamped to [1, 60] s, never
  overshoots its budget, and distinguishes a broker *decision* (`DenialError`,
  `TimeoutError`) from a failure to reach one (transport/parse errors → only
  these become `PAM_AUTHINFO_UNAVAIL`).
- **(#121)** The C module and the Go client disagreed on login-type
  classification, so the broker could apply different per-login-type policy to
  the same login depending on which client ran: the C side matched
  `gdm`/`lightdm` as substrings, never matched `sddm`, and tested the TTY before
  the service (classifying a display manager on `tty1` as `console`). The
  classification is now a single documented function pinned to `GetLoginType` by
  a test.
- **Critical (#120): `pam_oidc.so` granted `PAM_SUCCESS` before device
  authorization completed.** `Broker.Authenticate` returns `success: true`
  *together with* `requires_device: true` when it has merely started the device
  flow, and `pam_sm_authenticate` tested `success` before it looked at
  `requires_device` — so with the shipped `auth sufficient pam_oidc.so` the auth
  stack was short-circuited and login granted the moment the broker replied,
  before the user visited the verification URL and before the broker performed
  identity binding (`username_claim`) and `require_groups`, which run afterwards
  in a background goroutine. `requires_device` is now checked first, and
  `success` alone is no longer treated as a grant.
- **(#120)** The module now completes the device flow instead of abandoning it.
  It displays the verification instructions, then polls `check_session` —
  reconnecting per attempt, since the broker serves one request per connection —
  at the interval the broker asks for in `metadata.polling_interval` (clamped to
  [1, 60] s) until the flow completes or the budget expires. Nothing called
  `check_session` before, so the device flow had no completion path at all.
- **(#120) Every non-success outcome now fails closed.** A refusal, a session the
  broker no longer has (`SESSION_NOT_FOUND`/`SESSION_EXPIRED`/`FORBIDDEN` — the
  broker deletes the session on identity mismatch, group denial and expiry), or
  an exhausted timeout all deny; broker error codes are mapped to PAM codes
  mirroring `errorCodeToPAMResult`. Only failing to reach an opinion at all
  (broker unreachable, unparseable response) returns `PAM_AUTHINFO_UNAVAIL`.
- **(#120)** `internal/ipc` now *requires* `user_id` on `check_session`,
  `refresh_session` and `revoke_session`. The broker compares it against the
  session owner to reject cross-user access, but the validator neither required
  nor validated it, so an absent `user_id` was compared as the empty string.
- **(#120)** `PAMMaxTries` was `24`, which is not a Linux-PAM result code
  (`PAM_MAXTRIES` is 11); returning it would have turned a deliberate
  rate-limit denial into an unrecognized error. The `PAMResultCode` constants are
  now taken from the PAM headers the module is compiled against instead of being
  copied by hand, since the values are not portable between Linux-PAM and
  OpenPAM.

### Fixed (BREAKING for PAM configs)
- **(#119) `pam_oidc.so` connected to the wrong socket and ignored its module
  arguments.** The compiled-in `SOCKET_PATH` was
  `/var/run/oidc-auth-broker.sock` while the broker listens on
  `/var/run/oidc-auth/broker.sock`, so a default install could never reach the
  broker and every authentication returned `PAM_AUTHINFO_UNAVAIL`. The default
  is now derived from, and matches, the broker's `server.socket_path` default.
- **(#119)** Added the `socket=<path>` module argument for non-default
  deployments. It must be absolute and must fit in `sockaddr_un.sun_path`;
  anything else is rejected with a log line and the default is kept, rather than
  being silently truncated to a path naming a different socket. `MAX_SOCKET_PATH`
  is now taken from the platform's `sun_path` (108 on Linux, 104 on Darwin)
  instead of being hardcoded.
- **(#119)** Unrecognized module arguments are now logged at `LOG_WARNING`
  instead of being silently dropped. **The example configs previously passed
  `config=`, `operation=` and `target_user=`, none of which the module has ever
  implemented** (and PAM does not expand `%u` in module arguments, so
  `target_user=%u` was always literal). These have been removed from
  `configs/pam/*`, `configs/pam/common-auth`, QUICK-START.md, DEPLOYMENT.md and
  the ssh-server test project; `configs/pam/README.md` now documents the two
  arguments that do exist (`debug`, `socket=`) and explicitly lists the ones that
  never did. `config=` is still accepted, with a warning, so existing PAM stacks
  keep working.

### Added
- **(#121)** `oidc-pam-helper -timeout` now bounds the device-flow wait rather
  than only arming a watchdog (default 90 s, matching the PAM module's
  `timeout=`); the outer watchdog fires 10 s later so an authentication that runs
  out of budget reports a denial instead of being killed. `PAMModule.AuthTimeout`
  exposes the same budget to embedders.
- **(#120)** `timeout=<seconds>` module argument bounding the wait for device
  authorization (default 90, range 10–900). The default sits below sshd's
  default `LoginGraceTime` of 120 s so an expired flow is reported as a denial
  rather than sshd dropping the connection; documented in
  `configs/pam/README.md`.
- **(#118) CI coverage for the PAM/cgo packages.** A new `PAM (cgo)` job installs
  `libpam0g-dev`/`libjson-c-dev` and runs `go vet ./pkg/pam ./cmd/pam-module
  ./cmd/pam-helper` plus `go test -race ./pkg/pam/...`; the `Lint` job now lints
  `./...` (every package, PAM included) instead of an allowlist that omitted
  `pkg/pam`, `cmd/pam-module`, `cmd/pam-helper` and `pkg/metrics`. Previously the
  security-critical PAM module was never vetted, linted, or tested by CI.
- `make verify-linux` plus `test/docker/Dockerfile.verify`: runs the full
  vet/test/lint sweep — including the cgo packages, which cannot compile on
  macOS — in a Linux container. Documented in CONTRIBUTING.md.
- `-Wall -Wextra` on the cgo `CFLAGS` for `pkg/pam` and `cmd/pam-module`, and
  `(void)` markers on the genuinely unused PAM entry-point parameters so the C
  bridge compiles warning-free.

### Fixed
- **(#118)** `oidc-pam-helper -version` now prints the build date and git commit
  (the `buildDate`/`gitCommit` ldflags targets were set by the Makefile but never
  read, which is what surfaced them as `unused` once linting covered the package).
- **(#118)** `TestServerInvalidSocketPath` no longer depends on the test process
  being unprivileged: it points the socket inside a regular file (`ENOTDIR`)
  rather than at a merely absent directory, which root would simply create.
- **(#118)** `test/integration` used a raw passphrase for
  `security.token_encryption_key`, invalid since the v0.4.0 breaking change; it
  now uses a base64 32-byte test key.

## [0.4.2] - 2026-07-09

### Security
- Bumped Go toolchain pin from 1.25.11 to 1.25.12 (latest patch release).
- Bumped `golang.org/x/crypto` to 0.54.0 (pulls `golang.org/x/sys` 0.47.0, `golang.org/x/text` 0.40.0). govulncheck reports no called vulnerabilities.
- Refreshed SECURITY.md: supported versions now 0.4.x, replaced stale "alpha / not audited" language with the pre-1.0 / internally-audited status, corrected the security-scanner list and documentation links, and documented identity binding + AES-256-GCM key handling.

## [0.4.1] - 2026-06-26

### Security
- Bumped Go toolchain pin from 1.25.10 to 1.25.11, resolving two Go standard-library advisories reported by govulncheck: GO-2026-5039 (net/textproto) and GO-2026-5037 (crypto/x509).

### Documentation
- Refreshed README for v0.4.0: corrected install instructions, required-config keys (`token_encryption_key`, `username_claim`), fixed broken documentation links, and updated the roadmap/status.

## [0.4.0] - 2026-05-30

### Changed (BREAKING)
- **(#95 M-1) `token_encryption_key` must now be a base64-encoded 32-byte key.**
  The key is used directly as the AES-256-GCM key; the previous PBKDF2 + static
  salt derivation has been removed (the static salt was shared across all
  deployments). A passphrase or wrong-length value is now rejected at startup.
  - **Migration:** generate a key with `oidc-admin gen-key` (or
    `openssl rand -base64 32`) and set it as `security.token_encryption_key`.
    The token store is in-memory only, so there is no persisted ciphertext to
    migrate — existing sessions simply re-authenticate after restart.

### Added
- `oidc-admin gen-key` subcommand that prints a new base64-encoded 32-byte
  encryption key.
- `security.ValidateKeyString` for startup key validation.

### Security
- **Critical (#90):** Bind the authenticated OIDC identity to the requested local username via `username_claim` before activating a session; previously any IdP user could log in as any local account (including root). Fails closed when `username_claim` is unset.
- **Critical (#91):** Harden authorized_keys writes against symlink/TOCTOU attacks — the root broker now refuses symlinked `.ssh`/`authorized_keys`, opens files with `O_NOFOLLOW`, and replaces files atomically (temp+rename) instead of following/truncating user-planted links.
- **High (#92):** Enforce `require_groups` — required group membership is now checked against the authenticated user's groups instead of being silently ignored.
- **(#95) M-7:** `validateUsername` is now a strict POSIX login-name allowlist and is applied in `RemoveExpiredKeys` (previously skipped).
- **(#95) M-8:** Reject SSH public keys containing embedded newlines (authorized_keys injection); `ValidateKeyFormat` now enforces this and is wired into `AddPublicKey`.
- **High (#93):** Validate the OIDC nonce in the device flow — `PollDeviceAuthorization` now rejects an ID token whose nonce does not match the one issued (replay protection); honors `allow_missing_nonce`.
- **High (#94):** Fix PAM module response framing — `receive_auth_response` now reads until the newline delimiter (looped `recv` with a poll-based timeout) instead of a single `recv`, preventing truncation of large broker responses; Go and C response buffers unified at 8192 bytes (L-12).
- **(#95) M-5:** Device-flow polling errors are mapped to a bounded error-code enum for the Prometheus `error_code` label instead of the raw error string (cardinality-DoS / info-leak fix).
- **(#95) M-6:** Metrics HTTP server now sets Read/ReadHeader/Write/Idle timeouts (Slowloris mitigation).
- **(#95) L-8:** Config validation requires OIDC issuer/endpoints (and provider endpoints) to use HTTPS; `http://` allowed only in development mode.
- **(#95) L-1:** Non-Linux peer-credential stub now fails closed (returns an error) instead of returning uid 0.
- **(#95) L-3:** Broker aborts startup if it cannot set the IPC socket permissions (was a non-fatal warning).
- **(#95) M-2:** Corrected the `NewEncryption` doc comment to match the actual PBKDF2 derivation; **L-17:** guarded `truncateString` against a panic when `maxLen < 3`.
- **(#95) M-3:** Audience (client_id) verification is now only skippable in development mode; production always verifies regardless of `verify_audience`, consistent with the auth-code flow.
- **(#95) M-4:** The device-authorization discovery fallback endpoint is now run through the same scheme/host validation as discovered endpoints instead of being used unvalidated.
- **(#95) L-2:** Darwin/FreeBSD peer-credential checks now reject an unexpected `Xucred` version (avoids misreading an unpopulated struct as uid 0).
- **(#95) L-4:** IPC server caps concurrent connections (bounded semaphore) so a peer cannot exhaust goroutines/FDs.
- **(#95) L-5:** Documented that `pam_sm_acct_mgmt` performs no authorization (auth phase is authoritative); deployments must not rely on the PAM `account` stack as the sole gate.
- **(#95) L-6:** `pam-helper` ignores caller-supplied `-config`/`-socket` when running as root, preventing redirection to a rogue broker.
- **(#95) L-7:** Unknown risk-policy conditions now log a warning instead of silently evaluating to false (visible misconfiguration).
- **(#95) L-9:** Audit overflow strategy defaults to `block` (backpressure) instead of silently dropping; `drop` must be explicitly opted into.
- **(#95) L-10:** Audit write failures are counted and exposed via `FailedWrites()` for alerting.
- **(#95) L-11:** Fixed a per-authentication json-c object leak in the PAM module's request builder.
- **(#95) L-14:** Documented that authorized_keys expiry parsing is best-effort and fail-safe (forged/malformed comments retain the key).
- **(#95) L-15:** Token-ownership comparison in `ValidateToken` is now constant-time.
- **(#95) L-16:** Added best-effort zeroization of the derived encryption key (`Encryption.Destroy`) and transient decrypt buffers.

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
