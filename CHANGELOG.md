# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **(#123): OAuth2 refresh tokens were held in plaintext on every session; the
  encrypted `TokenManager` was never called.** `NewTokenManager` was constructed
  and started, and `StoreToken` encrypts with AES-256-GCM, but no broker code
  path ever stored a token — so the documented "AES-256 encryption for token
  storage" applied to an empty store, while the real credentials sat in
  `Session.RefreshToken` as plaintext strings in a struct that is copied and
  passed around freely. The broker now stores tokens through the token manager
  and keeps only `Session.TokenID`; `RefreshSession` decrypts the refresh token
  for the duration of the call, stores the rotated token and revokes the
  pre-refresh entry. A structural test fails if any token-bearing field is added
  back to `Session`.
- **(#123)** Revoked and expired sessions now destroy their stored tokens
  (`RevokeSessionTokens`). Previously the session was dropped while its tokens
  stayed in the store until the tokens themselves expired — which can be well
  after the session, and a refresh token outlives the access token it renews. A
  refused cross-user revocation leaves the owner's tokens intact.
- **High (#122): `pam_sm_acct_mgmt` rubber-stamped the account stack.** It
  returned `PAM_SUCCESS` while performing no account-phase authorization at all,
  and the shipped configs listed it as `account sufficient pam_oidc.so`. A
  `sufficient` module that succeeds ends the phase, so that combination silently
  disabled every account check after it — `pam_time`, `pam_nologin`,
  `pam_access`, account expiry, `pam_unix`'s shadow checks — for every user. It
  now returns `PAM_IGNORE`: PAM does not count an ignored module toward the
  stack's result, so the modules after it decide, and a stack where *every*
  module ignores yields `PAM_PERM_DENIED` rather than admitting everyone.
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
- **(#122)** The example configs (`configs/pam/{ssh,login,su,sudo}`, the
  DEPLOYMENT.md snippets, `test-projects/ssh-server`) now use `account optional
  pam_oidc.so` and `password optional pam_oidc.so`. **Existing `/etc/pam.d/*`
  files that say `account sufficient pam_oidc.so` should be changed to
  `optional`**: with the `PAM_IGNORE` fix above such a line no longer
  short-circuits, but as written it still advertises an authorization the module
  does not perform. `password` is `optional` because `pam_sm_chauthtok` returns
  `PAM_AUTHTOK_ERR` (change passwords at the IdP) and as `required` would block
  password changes for local accounts too.
- **(#122)** Removed unreachable `auth required pam_unix.so` / `auth optional
  pam_group.so` lines that followed `auth requisite pam_deny.so` in the `ssh`,
  `su`, `sudo` and ssh-server-test configs, and corrected the comments — in
  several places the docs described that dead line as the emergency Unix
  fallback. `requisite` returns to the application immediately, so nothing after
  `pam_deny.so` ever runs: those stacks are OIDC-only. `configs/pam/README.md`
  and DEPLOYMENT.md now explain the phase semantics, how to enable a real
  fallback and what it costs, and why SSH public keys are the usual break-glass
  path.
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
- **(#124)** `oidc-admin status`, `health`, `sessions` and `keys` work. The broker
  now implements the `status`, `sessions_list` and `keys_list` IPC requests the
  CLI has always sent, backed by `Broker.Status()`, `Broker.ListSessions()` and
  `Broker.ListKeys()`. `status` reports the broker's version, start time, uptime,
  configured providers and session counts; `sessions` lists user, provider, login
  type, creation time and status, including **pending** device flows the user has
  not completed (a login that looks like it is hanging shows up here, which is
  usually the question being asked); `keys` lists each managed key's algorithm,
  size in bits, status and expiry. Listings carry no credentials — no tokens, no
  token IDs, no key material — and are sorted (sessions newest first, keys by
  username) so repeated runs are diffable. All of them require root, since the
  broker socket accepts uid 0 only; DEPLOYMENT.md documents the commands and the
  `sudo` requirement.
- **(#124)** `Session.LoginType`: the broker applied per-login-type policy without
  recording which login type a session was opened for.
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

### Changed
- **(#127)** The six pre-implementation design documents in the repository root
  (`oidc_pam_project.md`, `oidc_pam_comprehensive.md`,
  `oidc_provider_configuration.md`, `research_computing_oidc.md`,
  `tailscale_oidc_integration.md`, `cloudworkstation_oidc_integration.md` — 5,546
  lines) move to `docs/design/`, behind an index that says plainly what they are:
  aspirational, unmaintained, and not a description of the current system. Two of
  them are about separate projects. In the root they outnumbered the real
  documentation and read as if they described shipped behaviour. Nothing linked to
  them, and nothing was deleted.
- **(#125)** `Broker.selectProvider` takes no arguments. It accepted an
  `*AuthRequest` and a `*PolicyResult` and read neither, which is part of why it
  went unnoticed that the body was non-deterministic; nothing about the request
  influences the choice today.
- **(#124)** `Server.handleRequest` returns `any`, since the admin requests answer
  with their own shapes rather than squeezing a session listing into the fields of
  an authentication response. `internal/adminapi` and `cmd/oidc-admin` are covered
  by CI's vet, test and lint runs.
- **(#123)** `Session.RefreshToken` is replaced by `Session.TokenID`, and
  `TokenManager.StoreToken` now returns the ID it generated. Both are internal
  Go APIs (`pkg/auth`), not wire or config surface.

### Removed
- **(#127)** The committed build artifacts `integration-test` (11.2 MB) and
  `test-broker` (7.75 MB) — 19 MB of macOS arm64 binaries in the repository root,
  which every clone paid for and no build step consumed. They are untracked and
  ignored now. Note that this does not shrink the history: the blobs are still
  reachable from old commits, and removing them would need a rewrite, which is out
  of scope here.
- **(#126)** `pkg/policy` (`RiskEngine`, 548 lines plus 482 lines of tests). No
  package imported it. It is a second, parallel risk-scoring implementation; the
  live one is `PolicyEngine` in `pkg/auth/policy.go`, which is what the broker
  actually calls. Two engines with no shared interface and only one of them wired
  up is a standing invitation to fix the wrong one.
- **(#126)** `pkg/auth/auth_code_flow.go` (`StartAuthCodeFlow`,
  `ExchangeCodeForToken`, `AuthCodeFlowState`) and its tests. Nothing called them.
  The authorization code flow needs a browser redirect back to a local listener,
  which is not available at a PAM prompt on a headless host — the device
  authorization grant is the whole reason this project exists. Recoverable from
  git history if a web-based flow is ever added.
- **(#123)** `TokenManager.RefreshToken`, a stub that validated its arguments and
  then returned `"token refresh not implemented"`. Refresh is done by
  `Broker.RefreshSession` via the provider; the stub had no callers and only
  suggested a capability that did not exist.

### Fixed
- **(#127)** `.gitignore` no longer ignores `*.h`. The cgo bridge headers
  (`pkg/pam/cgo_bridge.h`) are source files, so the rule meant a newly added
  header would be skipped by `git add` without a word — in a project whose
  security-critical component is written in C. The final entry was also the
  single mangled line `*.c.o.claude/`, which matched nothing; it is now `*.c.o`
  and `.claude/`, as intended.
- **(#127)** SSH setup instructions use `KbdInteractiveAuthentication`.
  `ChallengeResponseAuthentication` was deprecated in OpenSSH 8.7 and is now only
  a legacy alias; the device-flow prompt reaches the user over
  keyboard-interactive authentication, so this directive is the one that has to be
  right. Corrected in `QUICK-START.md`, `configs/pam/README.md`,
  `configs/pam/ssh` and the test SSH server's `sshd_config`.
- **(#127)** `QUICK-START.md` no longer tells the reader to run `./test-broker`,
  a committed macOS arm64 binary that could not execute on the Linux hosts the
  guide targets. It uses `sudo oidc-admin status` and `sudo oidc-admin sessions`.
- **(#127)** `test/Dockerfile.integration` pins `golang:1.25.12-alpine`. It was
  pinned to `golang:1.21-alpine`, four minor versions behind the `go 1.25.12`
  directive in `go.mod`, so building it either failed outright or quietly
  downloaded a second toolchain.
- **(#126) Orphaned SSH keys are now swept.** `AuthorizedKeysManager.RemoveExpiredKeys`
  existed but was never called from anywhere, so the 24-hour cleanup it implements
  never ran. It matters because sessions live only in the broker's memory: a
  broker restart orphans every key it had issued, leaving `@oidc-pam-<timestamp>`
  entries in users' `authorized_keys` with no session left to revoke them — a
  working credential for whoever holds the private key. The session-expiry pass
  now sweeps the `authorized_keys` of each user whose session just expired, once
  per user rather than once per session. Keys without a parseable broker comment,
  and the user's own keys, are left alone. The sweep is bounded to users with an
  expiring session, so a user orphaned by a restart who has not logged in since is
  not reached; that avoids walking every home directory on the host from the
  broker.
- **(#125)** Provider selection is deterministic. `selectProvider` ranged over a
  Go map and returned the first login-enabled provider it happened to hit, so on
  a host with more than one such provider, consecutive logins could be sent to
  different identity providers at random — and `priority` was read from the
  config file and then never used. Candidates are now ordered by `priority`
  ascending (**1 is the most preferred**, matching every shipped config, where the
  primary provider is `priority: 1` and the failover provider is `priority: 2`),
  then by name so that equal priorities still order identically on every host and
  across restarts. A provider that omits `priority` sorts *after* every provider
  that sets one, so forgetting the field cannot promote a provider over the
  declared primary; negative values are treated the same way. Documented in
  `configs/CONFIGURATION-GUIDE.md`.
- **(#125)** `verification_only` is honoured. It was parsed and never read, so a
  provider marked "may confirm an identity, must not be logged in against" was a
  valid login target if `enabled_for_login` was also set. It is now excluded from
  login selection.
- **(#124) Every `oidc-admin` command that talks to the broker was silently
  broken.** The CLI sent `status`, `sessions_list` and `keys_list`; the broker
  implemented none of them, so each request fell through to
  `INVALID_REQUEST_TYPE`. The client decoded that error object into its own
  response struct — which shares no fields with it — and printed the resulting
  zero value: `status` reported a **running broker with an empty version and no
  uptime**, and `sessions`/`keys` reported "none". The request and response types
  now live in one place (`internal/adminapi`) instead of being declared once on
  each side, every admin response can carry an error the client checks, and a
  round-trip test fails if the two sides drift again.
- **(#124)** `oidc-admin` no longer opens a throwaway connection to decide
  whether the broker is running. It sends the real request: a broker that accepts
  connections but cannot answer them was previously reported as healthy. Requests
  are bounded by a 10-second deadline, so a broker that accepts and then goes
  quiet no longer hangs the CLI indefinitely.
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
