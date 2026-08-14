# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Release artifacts are now signed and carry build provenance (#180).** Until
  now the only integrity material published was a `.sha256` file uploaded to the
  same release page as the tarball it describes, which detects a corrupted
  download and nothing else — anyone able to publish a release could publish a
  matching checksum. For artifacts that include `pam_oidc.so`, loaded into every
  authenticating process including `sshd`, and a root-run broker, "where did this
  binary come from" should be answerable without trusting the release page.

  Each release now publishes, for both `amd64` and `arm64`: the archive, its
  `.sha256`, a cosign signature bundle (`.sigstore.json`), a single signed
  `SHA256SUMS` manifest covering every architecture, and a SLSA v1 build
  provenance attestation per archive (`actions/attest-build-provenance`).

  Signing is cosign *keyless*: the signer is the release workflow's own GitHub
  Actions OIDC identity, so no key material exists in this repository or in its
  secrets, and the identity an operator verifies is
  `https://github.com/scttfrdmn/oidc-pam/.github/workflows/release.yml@refs/tags/<tag>`.

  Signing runs in its own job, which holds `id-token: write` but not
  `contents: write`; the publishing job holds `contents: write` and cannot mint
  signatures. The workflow-level default dropped from `contents: write` to
  `contents: read`. The release workflow verifies its own signatures — with the
  same command the documentation gives users — before the release is created, and
  re-verifies them after the artifacts and signatures are reunited for publishing.
- Release archives now contain a `SHA256SUMS` manifest of the binaries they
  install, and the bundled `install.sh` verifies it before copying anything into
  `/usr/local/bin` or `/lib/security`, refusing to install on a mismatch
  (`OIDC_PAM_SKIP_VERIFY=1` overrides). The archive's own `.sha256` covers only
  the download; nothing checked the payload that actually reaches PAM.

### Fixed
- The README's release-download snippet still read `VERSION=v0.4.0`, two releases
  stale, and every `curl`, `tar` and verification command below it interpolates
  that value — so the new signature-verification instructions would have been run
  against a release that has no signature. `scripts/release.sh` now stamps that
  line alongside the version badge, and the release workflow's version check fails
  the release if it disagrees with the tag; previously it read only the badge and
  the CHANGELOG, which is why this drifted unnoticed.
- `gh attestation verify` is now given `--source-ref` in the README and in the
  generated release notes, matching `docs/verifying-releases.md`, which explains
  why: `--repo` alone is satisfied by any attestation this repository has ever
  produced.
- SECURITY.md's supported-versions table still claimed 0.4.x.

### Added
- `docs/verifying-releases.md`: the exact `cosign verify-blob` and
  `gh attestation verify` commands, including the `--certificate-identity` and
  `--certificate-oidc-issuer` values for this repository, what each check proves
  (and what it does not), offline verification, and the pitfalls of matching the
  signer identity with a regexp. Every release's notes now carry the same
  commands with the tag substituted in.

## [0.5.0] - 2026-08-14

### Security
- **High (#171): the SSH key a successful login was granted was written to a
  directory guessed from the login name, was never removed when the session ended,
  and accumulated one working credential per login.** The provisioning path was
  wrong at both ends: the key often did not arrive where sshd reads it, and when it
  did arrive nothing took it away again.

  The broker joined `/home` with the login name and wrote `<that>/.ssh/authorized_keys`.
  On any site whose homes are not literally `/home/<user>` — SSSD or LDAP with
  `/home/<domain>/<user>`, autofs, NFS, a home moved by hand — it created that
  directory itself, as root and mode 0700, wrote a key list sshd would never read,
  and reported the login as successful. The user was told they were authenticated
  and then could not log in, and on the next real login their own home was shadowed
  by a root-owned directory they could not write. The uid from the passwd database
  was never consulted, so nothing distinguished "this is the account's home" from
  "this is a directory belonging to someone else". Where the key *did* land, it was
  appended on every login and deduplicated only against byte-identical lines, so an
  account that logged in daily accumulated a live credential per login; each one
  carried no expiry sshd could see, so it stopped being limited at all the moment
  the broker forgot the session that owned it — which happens on every restart,
  since sessions are held only in memory. The shipped systemd unit set
  `ProtectHome=true`, which makes `/home` an empty tmpfs to the service, so on a
  host installed from it no key could be written at all.

  - Home directories now come from the account database, through
    `pkg/ssh.LookupAccount`: `os/user` first, then `getent passwd`. The fallback is
    not redundancy — the released broker is built `CGO_ENABLED=0`, and without cgo
    `os/user` parses `/etc/passwd` and never asks NSS, so every SSSD or LDAP account
    is invisible to it. `getent` asks NSS the way sshd and `login` do, bounded by a
    timeout and a `WaitDelay` so a wedged directory server cannot hold a login open.
    Nothing derives a home path any more, and a home that does not exist is refused
    rather than created.
  - The owning uid is checked, on the home directory, on `.ssh` and on
    `authorized_keys` through the open file descriptor. The account or root is
    accepted, which is what sshd's own `StrictModes` accepts; anything else is
    refused rather than written through. Files the root broker creates in a home are
    handed to the account.
  - A login installs exactly one broker key: every previous `@oidc-pam-` entry is
    dropped as it is written, and the account's own keys are left alone. The entry
    carries `expiry-time="…"`, so **sshd** enforces the key's lifetime whether or
    not the broker is running or remembers the session. Both the key store and the
    `authorized_keys` sweep now use the configured `token_lifetime`; both used to be
    hardcoded to 24 hours, so a site that had deliberately set `token_lifetime: 1h`
    still handed out keys good for a day.
  - **That option makes OpenSSH 7.7 or newer a requirement**, and it is now stated
    where an operator will see it: DEPLOYMENT.md's prerequisites, and README.md's
    platform table, which gains an OpenSSH column and marks Amazon Linux 2 and
    RHEL/CentOS 7 (both `7.4p1`) unsupported rather than "expected to work". sshd
    refuses an entire authorized_keys entry that carries an option it does not
    recognise, so on an older host every key the broker installs is rejected — the
    same "authenticated, then `Permission denied (publickey)`" outcome, reached a
    different way. The timespec is written in the host's own time zone, not UTC: the
    `Z` suffix meaning UTC is OpenSSH 9.1 and newer, and every sshd before that
    rejects the entry carrying it, which would have limited this to Debian 12-era
    hosts while breaking RHEL 8 and 9, Debian 11 and Ubuntu 20.04 and 22.04. The
    broker does not detect the local sshd version; whether it should, refuse to
    start, or make the option configurable is #199.
  - Startup revokes what the previous run left behind. The key store survives a
    restart even though sessions do not, so anything in it at startup belongs to no
    live session and its `authorized_keys` entry is removed.
  - A login whose key could not be provisioned is now denied instead of completed.
    It used to be activated and audited as `authentication_successful` with no usable
    key anywhere; the failure is recorded as `ssh_key_provisioning_failed` and the
    session is dropped, which the module already reports through
    `SESSION_NOT_FOUND` — no change to the broker↔module wire contract.
  - Revoking a key a later login had already superseded is no longer reported as
    `ssh_key_revocation_incomplete`. That event means a credential is still live
    (#165), and firing it for the ordinary two-logins case would have trained
    operators to ignore it.
  - `configs/systemd/oidc-auth-broker.service` sets `ProtectHome=false`, lists
    `-/home` in `ReadWritePaths` (`ProtectSystem=strict` otherwise makes it
    read-only) and declares `StateDirectory=oidc-pam`; `scripts/install-release.sh`
    creates `/var/lib/oidc-pam/{ssh-keys,locks}` at 0700, and DEPLOYMENT.md's unit
    matches the shipped one. The `-` prefix is load-bearing: systemd fails a unit
    whose `ReadWritePaths` names a path that does not exist, and the site told to add
    its own home path — `/export/home` and the like — is exactly the site with no
    `/home`, which would have got a broker that refuses to start.

  Coverage: `pkg/ssh` tests that a key is written to the home the account database
  gives and that nothing is created at `/home/<user>`, that a missing home is
  refused rather than created, that a foreign-owned path is refused, that a second
  login supersedes the first key while leaving the user's own, that the installed
  entry carries the `expiry-time` option, and that the sweep measures against the
  configured lifetime; `pkg/ssh/accounts_test.go` covers the NSS fallback, an
  unknown account, a wedged account database and the passwd fields that are refused;
  `pkg/auth` tests that a login whose key cannot be installed is denied and audited,
  that startup revokes a previous run's keys through `Start` itself, that
  `token_lifetime` reaches the key manager, and that a superseded revocation is not
  reported as incomplete; `pkg/ssh/docs_test.go` fails if DEPLOYMENT.md or README.md
  stops stating the minimum OpenSSH version, or if the timespec written is anything
  other than the form an older sshd parses; `cmd/broker` pins the unit's
  `ProtectHome`, its optional `-/home` and `StateDirectory`; and two e2e cases cover
  a second login replacing the first key and a broker restart sweeping the keys it
  had issued.
- **Medium (#188): stopping the audit logger discarded every record still
  queued, and a second `Stop` panicked.** `processEvents` selected on its stop
  channel and returned without looking at the buffer, so the events sitting in
  `eventChan` when the broker shut down were collected unwritten. The records
  most likely to be in that buffer are the ones logged immediately before
  shutdown — the tail of the audit trail, and the part an investigation into why
  a host stopped answering would reach for first. The default overflow strategy
  is `block` precisely so that load cannot cost a record; shutdown was throwing
  away the same records for free.

  - The worker drains the buffer on both exits (stop and a cancelled context),
    and `Stop` drains again afterwards, so a logger that was never started, or
    whose worker had already returned on a cancelled context, still writes what
    it accepted. `Stop` returning now means every accepted event is on disk.
  - Draining is bounded by a five-second budget, because an output can be
    arbitrarily slow: one unreachable HTTP sink costs up to three ten-second
    timeouts plus backoff for a *single* event, and the default buffer holds a
    thousand, so an unbounded drain could hold shutdown for hours. A shutdown
    that never finishes is worse than an incomplete trail, so the budget wins —
    and what it abandons is counted in `DroppedEvents` and logged with the
    number, since a gap nobody is told about is indistinguishable from nothing
    having happened.
  - `Stop` is idempotent (`sync.Once`). It closes a channel, and stopping on a
    shutdown path plus a deferred cleanup — the ordinary shape — used to panic
    with `close of closed channel`.
  - The four `pkg/security` cases that logged events and then read the file back
    synchronised on a fixed `time.Sleep`, which is an assertion about the
    scheduler: on a loaded machine the events were not written yet and the case
    reported the field it could not find rather than the event that never
    arrived. This is what turned up as an intermittent
    `TestAuditLoggerComplianceRequirements` failure in CI, with an identical
    missing-field list to the one the defect above produces on demand. They now
    stop the logger and read, and no longer bound the worker's life with a
    two-second context.

  Coverage: `TestStopWritesEventsStillQueued` (three events queued with no
  worker; the file is empty without the fix), `TestStopDrainsAfterTheContextIsCancelled`
  (an event logged in the window between cancellation and `Stop`),
  `TestStopGivesUpOnASlowOutput` (forty events behind a slow output with the
  budget shortened: unbounded, `Stop` takes 1.04s against a 50ms budget and
  counts nothing) and `TestStopIsIdempotent` (which panics without the `sync.Once`). Each was run
  against the defect reintroduced.
- **Medium (#172): `configs/pam/common-auth` put a 90-second interactive device
  flow in the auth stack of every service on the host.** `common-auth` is the file
  every Debian/Ubuntu PAM service `@include`s, so an operator who followed the
  install instructions in `configs/pam/README.md` got `pam_oidc.so` at the front of
  `su`, `sudo`, `gdm`/`sddm`, `polkit`, `login` and `cron` as well as `sshd`. Each
  of those then waited up to `timeout` seconds — 90 by default — for a human with a
  phone before falling through, and several of them can never satisfy a device flow
  at all: no controlling terminal, a conversation function that discards
  `PAM_TEXT_INFO`, or a graphical prompt that renders the QR code as a block of
  ASCII art. Nothing was admitted that should not have been, since the stacks fail
  closed on `pam_deny.so`; what broke was the machine's usability, and with no
  password fallback in the shipped stacks (#160) an auth stack that cannot complete
  is an operator locked out of their own host.

  - `configs/pam/common-auth` is deleted. The per-service files — `ssh`, `login`,
    `su`, `sudo` — are what this project ships, and each now says in its header
    that it belongs in that one service's `/etc/pam.d` file and not in the
    host-wide stack.
  - `scripts/install.sh` no longer inserts `@include common-auth` at the top of
    `/etc/pam.d/sshd`. That line both duplicated the distribution's own include
    further down the same file and, on a host that had taken the old `common-auth`
    advice, ran the device flow twice. It also no longer runs `sed` against an
    `/etc/pam.d/sshd` that does not exist, which aborted the install.
  - `configs/pam/README.md` loses its "for system-wide (be careful!)" install
    command and gains a section on why no host-wide stack is shipped;
    `DEPLOYMENT.md` and `QUICK-START.md` say the same where they tell an operator
    to edit a PAM file. The `QUICK-START.md` example also still carried defects
    fixed elsewhere long ago — an unreachable `pam_unix.so` line after `requisite
    pam_deny.so`, and `account required pam_oidc.so` — and now matches
    `configs/pam/ssh`.
  - The `su` and `sudo` headers claimed they maintained "traditional authentication
    for emergency access". They do not: the `requisite pam_deny.so` in both refuses
    anything OIDC did not accept, and a comment that misstates a stack's semantics
    is part of the same defect.
  - `README.md`'s platform table claimed Console and GUI support as **Stable** on
    five distributions. CI exercises `sshd` on one image — Debian 12, via
    `test/e2e` — so the table now says which cell that is, marks the console, `su`
    and `sudo` stacks as untested examples, and marks display managers
    unsupported, since no `gdm`/`sddm`/`lightdm` stack is shipped. The "Subsequent
    access uses cached SSH key" line is gone: `pam_oidc.so` sends no session ID
    with its request, so the broker has nothing to match a login against and every
    login runs a fresh device flow.

  Coverage: four tests in `cmd/pam-module/configs_test.go` that read the shipped
  files rather than describing them. A stack file must be named after a service
  that can complete a device flow and must not point at a host-wide stack;
  `pam_oidc.so` must carry a documented control flag for its phase (`auth
  sufficient` or `required`, every other phase `optional`) and never a bracketed
  skip count like the `[success=2 default=ignore]` that `common-auth` used; no
  `scripts/*.sh` may touch `common-auth` or `system-auth`; and every
  `configs/pam/<file>` a document or script names must exist, so a deleted stack
  cannot leave install instructions pointing at it.
- **High (#170): none of the configuration files this project ships could be
  loaded, and every security setting an operator wrote under a name the broker
  does not read was discarded in silence.** viper's `Unmarshal` drops unknown
  keys without a word, so `security.tls_verification.pin_certificates` — not the
  name of any field; pinning is `pinned_certificates` and takes SHA-256
  fingerprints, not a boolean — was accepted in six files and set to `true` in
  three of them, including `broker-enterprise.yaml`, which
  `CONFIGURATION-GUIDE.md` recommends as the production template. Everyone who
  followed it believed certificate pinning was on and had nothing of the kind.
  Worse were the files that could not start at all:
  `configs/production/broker-cloud.yaml` used `${VAR:-default}` shell
  interpolation that nothing expands, so sixteen of its values were the literal
  string and it failed to parse; `broker-enterprise.yaml` named audit output
  types (`remote_syslog`, `webhook`) that no constructor knows, which is a
  `log.Fatal` before the broker listens — an audit sink silently absent on the
  host that most wanted one. Both shipped for eleven releases.

  - `LoadConfig` now decodes with `UnmarshalExact`: an unknown key is a startup
    error naming its full path (`'security.tls_verification' has invalid keys:
    pin_certificates`). A key the broker does not read is a setting that does
    nothing, and a setting that does nothing must not look like protection.
  - Because the shipped PAM stack has no password fallback (#160), a config that
    loaded yesterday must not become an unbootable host:
    `OIDC_AUTH_ALLOW_UNKNOWN_CONFIG_KEYS=true` downgrades the error to a warning
    naming the keys, for recovery only.
  - `pin_certificates` corrected to `pinned_certificates` in all six files;
    `broker-cloud.yaml` deleted (the `cloud:` subtree it existed for was never
    read — `env:` and `file:` secret references are how secrets stay out of the
    file); the inert `cloud:`, `ssh:`, `policy:`, `logging:`, `health:` and
    `metrics:` blocks removed, with a note pointing at the settings that are
    actually enforced. `security.encryption_key`, `oidc.timeout` and the
    `monitoring:`/`network:` blocks are gone from QUICK-START.md and
    DEPLOYMENT.md for the same reason, and the guide now documents the live
    knobs no template showed (`server.metrics_addr`, `socket_group`,
    `audit.overflow_strategy` and the rest).
  - `security.ValidateAuditConfig` checks output types, paths and
    `overflow_strategy` up front, so an unknown `overflow_strategy` no longer
    degrades quietly to `drop`.

  Coverage: `TestShippedConfigsLoad` puts every YAML under `configs/`, plus
  `test/e2e/broker.yaml`, through `LoadConfig` → `Validate` → the audit check
  the broker performs at startup, and `TestDocumentedConfigSnippetsLoad` holds
  the YAML in README/QUICK-START/DEPLOYMENT/CONFIGURATION-GUIDE to the same
  standard, since a wrong key in a document is a key somebody pastes into
  `broker.yaml`. Proven against the defect: restoring the old files fails seven
  of the config cases and five of the document cases, naming `cloud`, `logging`,
  `policy`, `ssh`, `format` and `pin_certificates` by path.
- **High (#169): the network access controls could not work, and every audit record
  named the client as the host being logged into.** Neither client ever sent
  `source_ip`, and both sent `PAM_RHOST` — the address the login comes *from* — as
  `target_host`, so the two ends of the connection were swapped on the wire. Every
  policy that reads `source_ip` was therefore evaluating the empty string:
  `require_private_network` and `require_tailscale` ask `net.ParseIP` about it, which
  answers no, so enabling either refused **every login on the host** including the
  ones it was configured to admit — and `configs/production/broker-enterprise.yaml`
  ships with both on. `ip_allowlist`/`ip_denylist` and the geo checks matched nothing
  for the same reason, the location history recorded an entry with an empty subnet
  that made every subsequent login for that user score as an unusual location, and
  the audit trail recorded the client's address in `target_host` — so an
  investigation could not tell which machine a login reached.

  - Both clients now send `source_ip` from `PAM_RHOST` and `target_host` from this
    host's own name, per the **oauth2-pam wire protocol (version 1)**: `source_ip` is
    "the client address, if the login has one and it really is an address" and
    `target_host` is "the host being logged **into** — this host". That project owns
    the contract and this one consumes it (#179), so the field meanings, the 45- and
    253-byte bounds and the decision to leave `source_ip` optional are taken from
    there rather than settled here.
  - A resolved hostname is not an address, so an `rhost` that is a name (what sshd
    supplies with `UseDNS yes`) yields no `source_ip` rather than a string no policy
    can evaluate. The unabridged `rhost` reaches the broker in `metadata.rhost`, as
    audit context that nothing consults for a decision.
  - **An absent `source_ip` is now a third answer — "origin unknown" — and what it
    means is the operator's, not the zero value's.** A console login legitimately has
    no address, so a network requirement now needs
    `authentication.network_requirements.unknown_source_ip: deny|allow` alongside it;
    the broker refuses to start with the requirement enabled and the question
    unanswered, rather than reaching the old implicit answer (deny everything) at the
    first login. `allow` is audited per login as `network_requirement_waived`: a
    requirement that was configured and then not applied must not be invisible. Risk
    scoring counts an unknown origin the same 25 as a public one — it is not evidence
    of safety — but names it "Unknown network origin" so the score can be read.
  - A login with no location is no longer recorded in the location history at all,
    which is what turned one unrecordable first login into a permanent "unusual
    location" verdict for that user.
  - `internal/ipc` now bounds `source_ip` at 45 bytes and `target_host` at 253 at the
    boundary, and accepts a zoned IPv6 literal (`fe80::1%eth0`), which `net.ParseIP`
    rejects on its own.
  - Coverage on both sides of the boundary, since the defect was identical in each: a
    cgo test asserting what the C module puts on the wire, a Go test doing the same
    against a fake broker, policy tests that a private source address is now
    distinguishable from a public one (impossible to write against the defect — both
    cases were the empty string and both were denied), a config test that every
    shipped config answers the unknown-origin question, and an e2e case asserting the
    login came from `127.0.0.1` and arrived at this host. Each was proven to fail with
    the defect reintroduced.
- **High (#168): the shipped PAM stacks logged every login's broker response to
  syslog, and a service with no PAM conversation crashed the login outright.** Five
  defects in the C module, grouped because they are one PR's worth of work.

  - `display_message` called through `conv->conv` on the strength of
    `pam_get_item(PAM_CONV, …)` answering `PAM_SUCCESS`, which it does even for a
    service that set no conversation function. Showing the device-flow instructions
    then jumped to address zero and killed the auth child — under sshd that child
    *is* the login. Both the item and the function pointer are checked now, and a
    message that cannot be shown is logged and skipped instead.
  - `get_user_info` applied its `"unknown"`/`"localhost"` substitutes only when
    `pam_get_item` *failed*. An item a service never set comes back as
    `PAM_SUCCESS` with a NULL pointer, and the next thing that happens to it is
    `json_object_new_string()`, i.e. `strlen(NULL)`. `PAM_RHOST` is not set by
    services that are not remote and `PAM_TTY` not by services with no terminal, so
    this was reachable from any non-sshd stack — `su`, `sudo`, `login`, cron — and
    not from something exotic. Found while writing the test for the defect above,
    which crashed on this one first; fixed with it.
  - `debug_enabled` was a process global that was set and never cleared, so a single
    `debug` anywhere turned on debug logging for every *later* authentication in the
    process — and `pam_sm_authenticate` runs inside sshd, which serves many logins
    from one process and may run more than one service's stack there. What that
    logged included the **entire broker response**: the live device code, the user's
    email and groups, and whatever the broker↔module contract grows next. The flag
    is now taken from each invocation's own arguments (`pam_oidc_options.debug`), a
    response is logged by size and never by body, and the shipped `ssh` and `login`
    stacks no longer pass `debug` — they used to, next to a note telling the reader
    to remove it, which is not a default.
  - `classify_response` read the grant condition with `json_object_get_boolean`,
    which answers true for any non-empty JSON *string*: `"success":"false"` was a
    success, and under `auth sufficient pam_oidc.so` a success is a login. The field
    must be a JSON boolean now. The broker emits one, which is why insisting on it
    costs nothing in the one function whose whole job is to be strict about the
    grant.
  - The unused `prompt_user`, which copied a conversation reply into a buffer whose
    size only its caller knew, is deleted rather than left to be wired up. This
    module never prompts: the device flow happens in the user's browser.

  Coverage: three cgo tests against a fake broker, two of them driving
  `pam_sm_authenticate` itself so that argument parsing is part of what is
  exercised — an authentication whose PAM handle carries no conversation function
  (a segfault before the fix), a second authentication in the same process not
  inheriting the first's `debug`, and `success` as the string `"false"`, the string
  `"true"`, `1` and `null` each refused rather than granted. A fourth test reads
  `configs/pam` and fails if a shipped stack passes `debug`.
- **Medium (#167): a token response with no `id_token` was accepted with nothing
  verified at all, an unsigned `/userinfo` body outranked the signed token where the
  two disagreed, and two of the three endpoints the broker sends credentials to were
  never checked.** The whole verification block in `PollDeviceAuthorization` —
  signature, `iss`, `aud`, `exp`, the nonce replay check and `validateIDTokenClaims`
  — sat behind `if tokenResp.IDToken != ""`, so a provider that simply omitted the
  field got an identity read out of `/userinfo` and vouched for by nothing but TLS
  and the bearer token. Where an ID token *was* present, the merge that decides which
  claim authorizes the login preferred `/userinfo` anyway. The endpoint gap is the
  sharpest of the three and needs no misbehaving provider: `validateEndpoint` ran on
  the device authorization endpoint only, while the token and userinfo endpoints were
  taken from the discovery document unvalidated, so a discovery response naming
  `http://` had the broker post the device code to, and carry the access token to, a
  plaintext endpoint — with `trusted_ca_bundle`, `skip_tls_verify` and the
  certificate pins all bypassed, because none of them apply to a connection that
  never negotiates TLS.

  - `require_id_token`, per provider, defaults to **on**: a granted authorization
    with no `id_token` is refused, leaves no session and no SSH key, and is audited
    as `ID_TOKEN_MISSING` naming the key that would permit it. The field is a
    `*bool`, so unset means required in configs built in Go as well as in loaded
    YAML — the fail-closed direction for every deployment that has never heard of
    the key. An operator whose provider genuinely does not issue an ID token for the
    device grant sets it to false and gets the old behaviour, deliberately.
  - The ID token now wins over `/userinfo` wherever the two disagree. Claims only
    `/userinfo` returns are still used, since the signed token says nothing about
    them, so this changes which value is believed in a conflict and not how much of
    the identity is available.
  - The token, userinfo and device authorization endpoints are all checked when the
    provider is built, which refuses a provider like this at broker startup rather
    than one login at a time. Only the scheme is enforced there, deliberately: a
    token endpoint on a host other than the issuer's is ordinary — Google's issuer
    is `accounts.google.com` and its token endpoint is on `oauth2.googleapis.com` —
    so extending the issuer-host match that the device endpoint has always demanded
    would refuse real providers outright. What an endpoint cannot be is plaintext.
  - Loopback is still exempt from that check, for local development and the test
    issuer, but is matched exactly now rather than by prefix: the old
    `strings.HasPrefix(u.Host, "localhost")` took `localhost.attacker.example` for
    the local machine and allowed plaintext to it.
  - Out of scope, and both left alone on purpose: refresh responses, where RFC 6749
    §6 makes `id_token` optional and the refresh path derives no identity from
    claims; and `security.tls_verification.pin_certificates` as documented in
    `CONFIGURATION-GUIDE.md`, which matches no config field and so pins nothing
    (#170).

  Coverage: five tests in `pkg/auth/provider_trust_test.go`. Three drive the real
  poll loop against the in-process issuer — a grant with the `id_token` withheld
  refused and audited as `ID_TOKEN_MISSING`; the same grant admitted under
  `require_id_token: false`, so the escape hatch is known to work; and an ID token
  and a `/userinfo` body naming different users, asserted in both directions, so
  that the signed claim is the one that binds *and* the unsigned one cannot
  authorize a login the signature contradicts. The other two go through
  `NewOIDCProvider` against a discovery document naming `http://` for each endpoint
  in turn, and against configured endpoints under `skip_discovery`, including the
  `localhost.…` host and a legitimate cross-host HTTPS token endpoint that must
  still be accepted. Reintroducing any one of the three defects fails the
  corresponding test.
- **Low (#166): `allowed_groups` and `allowed_roles` denied nothing.** Both were
  applied while claims were being read, where the only thing they could do was drop
  the group and role names that were not in the list. A user in **none** of the
  `allowed_groups` therefore reached the login decision with an empty group list and
  was authenticated normally — the option that reads as an authorization gate was a
  projection. The only thing that would have caught it is the global
  `authentication.require_groups`, which is empty in every shipped config and, until
  #158, was the only group key enforced at all. The severity is Low only because the
  keys appear in no shipped YAML and in no document, so no deployment relies on
  them; the exposure was to the first operator who found the struct field and
  assumed the obvious meaning.

  - Both are now login gates, enforced on the device-flow poll path in
    `Broker.verifyGroupAuthorization`: a non-empty list the identity satisfies
    nothing in refuses the authentication, leaving no session and no SSH key. An
    empty list still means no restriction, which is what every existing deployment
    depends on.
  - They no longer touch the group or role list. `extractUserInfoFromClaims`
    reports the identity as the IdP asserted it (`group_prefix` and
    `group_mappings` are still projections), so the session, the audit record and
    `require_groups` all see the same groups. Under the old code an identity that
    *did* satisfy `require_groups` could be refused by it, because the allowlist had
    already removed the group it was being required to have.
  - `require_groups` and the allowlists meet in one function rather than becoming
    two competing checks, because they ask different questions and cannot be one
    list: `require_groups` demands *every* group it names, an allowlist demands *at
    least one*. Refusals are audited apart — `GROUP_NOT_ALLOWED` against
    `GROUP_DENIED` — since they send an operator to different config keys.
    Case-insensitive matching for the allowlists is kept as it was, so this changes
    what a non-match does and not what matches.

  Coverage: five cases in `device_poll_test.go`, all through the real poll loop as
  #158's are — refusal with no session, no key and no success record; a member
  admitted with *all* of its groups; an empty list restricting nothing;
  `allowed_roles` on its own; and the three-way composition with `require_groups`.
  Re-applying the filter makes four of them fail, one of them (`required but not
  allowed`) by demonstrating the interaction above.
- **High (#165): after any expiry sweep, the next login's SSH key became
  permanently unrevocable while the audit log reported it as revoked.** The sweep
  rewrote `authorized_keys` from a `bufio.Scanner`, which strips newlines, and
  joined the survivors without restoring the final one — so the file was left
  unterminated. `AddPublicKey` appends with `O_APPEND`, so the user's next login
  fused its `# Added by OIDC PAM on …` comment onto the last surviving key line.
  sshd still honours the key on such a line, but nothing can remove it again: the
  sweep can no longer parse the timestamp out of `…@oidc-pam-1770000000# Added by…`
  and so retains the key (fail-safe by design), and targeted revocation compares
  the whole line and no longer matches. `RemovePublicKey` returned `nil` for "no
  such line" exactly as it did for a real removal, so the broker went on to log
  `SSH key revoked` at Info and record a revoke-success metric for a removal that
  changed nothing. No attacker is needed: one expired key plus one later login.

  - Both rewrite paths now go through one writer, `writeAuthorizedKeysLines`, which
    guarantees the file ends in exactly one newline. The two paths previously
    derived the file's tail independently — `RemovePublicKey` split on `"\n"` and
    happened to be correct, the sweep did not — and sharing the writer is what
    stops them disagreeing again.
  - `AddPublicKey` terminates an unterminated last line before appending, so a file
    left that way by anything else (a user's editor, a broker from before this fix)
    cannot fuse the next key either.
  - `RemovePublicKey` now returns `(removed bool, err error)`. A caller cannot
    silently mistake "there was no such line" for "the line is gone"; `removed=false`
    with a nil error means the entry is still there.
  - `revokeSSHKey` audits the two outcomes separately: `ssh_key_revoked`
    (`success=true`) only when an `authorized_keys` line was actually removed, and
    otherwise `ssh_key_revocation_incomplete` with
    `ErrorCode=AUTHORIZED_KEYS_ENTRY_NOT_REMOVED` and a revoke-**failure** metric,
    naming the user and session so an operator can find the file.
  - Note for operators: entries already fused by this defect are not repaired by
    the fix — they are indistinguishable from a legitimate key whose comment field
    contains a `#`. Grep for `# Added by OIDC PAM` on a line that does not start
    with `#` and delete those lines by hand.
- **High (#164): if the identity provider stopped returning the configured
  `username_claim`, the authorization decision moved silently to `sub`.** An absent
  `preferred_username` or `sub` claim was substituted with `userInfo.Subject`, and an
  absent `email` with `userInfo.Email`, so a scope change, a claim-mapper edit or a
  tenant migration re-pointed identity binding at an identifier the operator never
  chose and never audited — without an error, a warning or an audit record. The claim
  it fell back to is the one shipped in every provider config
  (`preferred_username` in `azure-ad.yaml`, `okta.yaml`, `keycloak.yaml` and
  `test/e2e/broker.yaml`), and for the many IdPs whose `sub` is an email or a
  username — LDAP/AD-backed and self-hosted ones especially — that substituted value
  was then matched against local account names, so #159's local-part matching applied
  to it too.

  - The configured claim is now the only claim consulted. A token that does not carry
    it is refused: no session, no login key, and no token stored.
  - The refusal names the claim that was configured and missing, and points at the
    provider's scopes and claim mapping. A `sub`-based deployment stays expressible,
    deliberately, as `username_claim: sub`.
  - Audited as `USERNAME_CLAIM_MISSING` rather than `IDENTITY_MISMATCH`: nothing was
    wrong with the identity, every login through that provider is failing for the same
    reason, and the fix is in the provider or the config.

  Coverage: the existing "claim absent in token fails closed" case passed against the
  defect because its fixture had an empty `Subject`, which is exactly the condition
  that hides the fallback. The new cases give the identity a non-empty `Subject` and
  `Email`, cover all three deleted branches, and run through the full device flow —
  proven to fail with the fallback restored (an active session, a provisioned key and
  an `authentication_successful` record).
- **High (#161): any local user could stop session expiry and key revocation for
  the whole host.** The broker serialized its `authorized_keys` writes on
  `~/.ssh/authorized_keys.lock` — a path inside the home directory of the very
  account it was protecting — and took it with a *blocking* `flock(LOCK_EX)`. So
  `flock ~/.ssh/authorized_keys.lock -c 'sleep infinity'`, which needs no
  privileges, parked the broker's only cleanup goroutine indefinitely: from then on
  no session expired, no key was revoked for *any* user, and `Broker.Stop()` — which
  waits on that goroutine — hung, so `systemctl restart` waited out
  `TimeoutStopSec` and ended in SIGKILL. A login's `AddPublicKey` blocked the same
  way, holding the authentication open until sshd's `LoginGraceTime` killed it.

  - The lock moved out of the user's home to `/var/lib/oidc-pam/locks/<user>.lock`
    (`ssh.DefaultLockDir`), a root-owned 0700 directory. A lock whose only job is
    to serialize the broker against itself has no business being reachable by the
    account it protects. The broker refuses to use a lock directory that is a
    symlink, is not a directory, is group- or world-writable, or is owned by
    another uid.
  - Acquisition is now `LOCK_EX|LOCK_NB` with a bounded retry (5 s, 50 ms apart)
    and returns `ssh.ErrLockUnavailable` instead of waiting. This is what makes the
    fix durable: no future lock location, and no misconfigured state directory, can
    park the daemon again. A failed acquisition skips that one user's write — the
    sweep is best-effort and is retried on the next pass — rather than writing
    without the lock.
  - `NewAuthorizedKeysManager` takes the lock directory as a second argument. It is
    required rather than defaulted, so a caller cannot arrive at a lock directory
    inside a user's home by omission.
  - `configs/systemd/oidc-auth-broker.service` adds `/var/lib/oidc-pam` to
    `ReadWritePaths` (`ProtectSystem=strict` made it read-only) and
    `scripts/install.sh` creates `ssh-keys/` and `locks/` at 0700.
- **High (#160): one unauthenticated remote client could make a host
  unloginnable.** The IPC rate limit was documented and named as per-UID, but the
  UID it was keyed on can only ever be 0 — `verifyPeerCredentials` rejects every
  peer that is not root — so there was a single bucket for the whole machine and
  `max_requests_per_minute` was a *host-wide* budget. One PAM login spends about
  19 requests (one `authenticate` plus a `check_session` per poll), so the shipped
  budgets of 30–60 covered under three concurrent logins. Opening SSH connections
  to any syntactically valid username at roughly one per second emptied it, after
  which every login on the host was refused with `RATE_LIMIT_EXCEEDED` →
  `PAM_MAXTRIES`, and the shipped stack (`auth sufficient pam_oidc.so` followed by
  `auth requisite pam_deny.so`) has no password fallback. The bucket refilled at
  30–60 tokens per minute, so a slow trickle sustained it.

  - The limits are now keyed on the **account a request names**, so one account's
    traffic cannot spend another's budget. `max_requests_per_minute` is therefore
    now a per-account figure; the shipped values are unchanged and are generous
    for one account.
  - `check_session`, `refresh_session` and `revoke_session` are charged against a
    separate, larger budget (20× the authenticate budget, one per poll of one
    login). Sharing one budget meant that exhausting it refused the polls of
    logins already in flight: the broker permitted the login, chose the polling
    interval itself, and then denied the login for continuing.
  - The limiter runs after the request is decoded and validated, since that is
    when the account is known. As the compensating bound, `maxRequestSize` drops
    from 1 MiB to 64 KiB — the largest request these validation limits permit is
    about 40 KiB — so what an unlimited peer can make the broker allocate is
    8 MiB rather than 128 MiB.
  - The bucket map is bounded (4096 entries, LRU eviction), because its keys now
    come from requests. Eviction cannot be turned into a lockout: draining a given
    account's budget requires naming it, which keeps that bucket the most recently
    used and so the last evicted.
  - Administrative reads (`status`, `sessions_list`, `keys_list`) are not charged.
    They name no account, so they would all share one bucket — the shape of this
    bug — and an `oidc-admin status` refused during an incident is a real cost
    where an operator looping the command is not a threat.

  This does not stop an attacker from spending the budget of an account they name
  deliberately; that needs a second key the client does not choose (`source_ip`,
  #169) and the pending-flow accounting in #163.

  Coverage: `ratelimit_test.go` drove the limiter with synthetic uids 1000/2000/3000
  — a state unreachable in production, and the reason a host-wide bucket looked
  per-user in the tests. It is rewritten around account names, with the attack as
  a test (400 requests naming 100 accounts, then a login for an unnamed account
  still succeeds) and one asserting an in-flight login's polls survive an
  exhausted authenticate budget.

- **High (#159): an identity provider could choose which local account a login
  became, including root.** Identity binding accepted the **local part** of an
  email-shaped claim as a match for the requested account, so `root@evil.tld`
  logging in as `root` was bound and approved. With `auth sufficient pam_oidc.so`
  (the shipped stack) that short-circuits the rest of the auth stack. Reaching it
  needed only the ability to choose the local part of one's own address — a mail
  alias, a second verified domain, a B2B guest identity from another tenant —
  and the branch was live in every shipped configuration: `username_claim: email`
  in four of them, and `preferred_username`, which *is* the UPN on Entra ID, in
  two more. The weaker variant needed no provider control at all: guest
  `alice@partner.example` and employee `alice@example.com` both bound to local
  `alice`.

  Two independent fixes, either of which stops the escalation:

  - The whole claim value must now equal the requested account. Local-part
    matching is opt-in per provider (`username_claim_strip_domain: true`) and
    requires `allowed_email_domains` to pin the domains it may come from —
    enabling one without the other is a startup error, and domains are matched
    exactly, since a wildcard re-opens the subdomain an attacker can get a
    verified address under.
  - No OIDC identity may bind to uid 0 or to any account with uid below 1000,
    whatever the token says and however the mapping is configured. This is the
    check that holds when `username_claim` or `allowed_email_domains` is wrong.
    Deliberate exceptions go in `authentication.allow_privileged_accounts`, named
    one at a time, and each use is logged.

  Refusals of the second kind are audited as `PRIVILEGED_ACCOUNT_DENIED`: the
  identity matched, so recording it as `IDENTITY_MISMATCH` would send an operator
  looking for a claim problem that is not there.

  **This is a breaking change for anyone using an email-shaped
  `username_claim`.** Logins that relied on the local part being stripped will be
  refused until `username_claim_strip_domain` and `allowed_email_domains` are
  set; the refusal names both keys and the domain it saw. The six affected
  shipped configs are updated with the opt-in and a placeholder domain. The
  environment-variable-derived config deliberately does *not* enable it, because
  it cannot know the operator's domain and guessing a domain pin is the wrong
  direction to fail.

  Coverage: the previous test suite asserted the vulnerable behaviour was correct
  (`identity_binding_test.go` had `email: alice@example.com` + requested `alice`
  ⇒ no error), which is why it survived. That case now asserts the refusal and
  moves under the opt-in. `root@evil.tld` is tested against all four plausible
  provider configurations, the uid guard is tested on an exact claim match, and
  both run through the full device flow — not just the binding function — so the
  poll loop is proven to act on the result. Two e2e cases: an exactly-matching
  identity refused for a uid-400 account (`root` is unusable there, since
  `PermitRootLogin no` means sshd refuses before PAM runs and the case would pass
  without testing anything), and `alice@example.org` refused for local `alice`.

### Fixed
- **High (#162): a verification URL longer than about 100 characters made every
  login on the host fail, with nothing to go on but "Failed to parse broker
  response".** The module read a broker response into an 8 KiB buffer, and the
  verification URI reached it three times over: as `device_url`, as text inside
  `instructions`, and as QR art whose size grows with the URI — art the broker
  serialized *twice*, once as its own `qr_code` field and again embedded in the
  instructions. An ordinary device response therefore sat about 20 bytes from the
  limit. Past it, what arrived was a truncated prefix, `json_tokener_parse` refused
  it, and the login was refused with `PAM_AUTHINFO_UNAVAIL` — the same result as a
  broker that is not running, so the shipped stack's `auth requisite pam_deny.so`
  left the operator with no password fallback and no diagnosis. Every provider in
  the wild hands out a short URI, which is why nothing caught this.

  - The QR art is serialized once, inside `instructions`. The redundant `qr_code`
    field is gone from the IPC response (and from `internal/brokerclient`, which
    declared it and never read it).
  - The broker now owns the size of what it sends. A device response that would not
    fit the module's buffer is re-rendered **without the QR art** — a login the user
    completes by typing the URL beats a response that cannot be parsed — and at the
    write site a response that still does not fit is replaced by a small, parseable
    `RESPONSE_TOO_LARGE` failure rather than a truncated prefix of the real one.
    Admin payloads are deliberately exempt: `oidc-admin` decodes a stream, and
    `sessions_list` on a busy host is legitimately larger than the module's buffer.
  - The buffer is 16 KiB, the bound the **oauth2-pam wire protocol (version 1)**
    sets on a response. That project owns the broker↔module contract and this one
    consumes it (#179), so the size is taken from there rather than chosen here.
    `MAX_RESPONSE_SIZE` and `internal/ipc`'s `maxResponseSize` are held equal by a
    test that reads the C header, so the two cannot drift; the second, unused
    `MAX_BUFFER_SIZE` macro that had the same value is gone.
  - `receive_auth_response` no longer reports success on a full buffer with no end
    of message. That case is now distinguished from a transport failure and reported
    as `PAM_SERVICE_ERR` ("error in service module"), not `PAM_AUTHINFO_UNAVAIL`
    ("could not reach an opinion"), with the size in syslog. Both fail closed, but
    they no longer look alike to whoever is reading the log.
  - The broker bounds what a provider can hand it: `verification_uri` and
    `verification_uri_complete` at 512 bytes, `user_code` at 64, rejected with an
    error naming the provider's field — the input side of the same problem, where
    the error can still say where the value came from.
  - Tests in three places, since this defect lived between them: a Go test that
    marshals the worst-case response the broker's own validation permits and asserts
    it fits (with the art, and without); a cgo test that an oversized response is
    reported distinctly rather than as an unreachable broker; and an e2e case that
    logs in against an issuer handing out a 400-byte verification URI, asserting the
    URL still reaches the user and the module never falls back on a parse failure.
    `fakeoidc` grew a `/control/verification-uri?pad=N` route for it, because a
    harness that only ever sees a 29-byte URI cannot tell that this is broken.
- **High (#158): `require_groups` written the way every document tells operators
  to write it enforced nothing.** Group membership was checked against the global
  `authentication.require_groups`, but the configuration in QUICK-START.md,
  DEPLOYMENT.md and the provider examples puts `require_groups` under
  `authentication.policies.<name>`. The policy engine collected those into
  `PolicyResult.RequiredGroups` and nothing ever read it, so on the documented
  configuration any identity the provider would authenticate received a login,
  a session, and an SSH key. `pollDeviceAuthorization` now enforces the list the
  policy engine resolved — the union of the global setting and every matching
  policy — which it takes as an argument, because the check runs in a background
  goroutine long after policy evaluation and re-evaluating there would evaluate
  against a different clock.

  Two things prevented that resolved list from ever containing anything:

  - Policies were matched against `AuthRequest.TargetHost`, which despite its
    name is populated from PAM's `PAM_RHOST` by both clients — the address the
    user is connecting *from*. A policy named `production` therefore only matched
    a *client* literally named `production`. Matching is now against the
    hostname of the machine being logged into, which is what a policy naming a
    resource means.
  - No policy name in any shipped configuration is a hostname; they are all
    `default`, `production`, `staging`. `default` is now a documented catch-all
    that applies to every host, so `policies.default.require_groups` — the
    QUICK-START configuration — is enforced.

  Policies whose names cannot match this host are logged by name at startup
  instead of silently doing nothing, and `applyResourcePolicies` now applies
  *every* matching policy rather than ranging over a map and breaking on the
  first, which made the effective policy vary between runs of the same binary on
  the same host. Unioning `require_groups` and taking the minimum
  `max_session_duration` means an additional match can only restrict access
  further.

  `configs/CONFIGURATION-GUIDE.md` documents how a policy is selected;
  DEPLOYMENT.md's example no longer uses three keys that are not fields of a
  policy (`session_duration`, `max_concurrent_sessions`, `require_mfa`) or two
  names that can never match (`admin_operations`, `sudo_operations`). Policies
  still cannot be scoped to an operation such as `sudo`.
- **Medium (#153): every `authentication_successful` record was written without
  the identity it authenticated.** The device-flow poll loop clones the session
  before mutating it (the map holds the raw pointer, so writing through it would
  race with readers) and writes the email and groups from the provider onto the
  clone — but the success audit event was built from the *original*, so it reached
  the audit trail with `email: ""` and `groups: null` on every login. The denial
  events, built from the provider's user info directly, carried the identity
  correctly, so an operator reviewing the trail could see who had been refused but
  not who had got in. The event now reads the clone it belongs to, as does the
  location the policy engine records.

  `device_authorization_failed` also gains the `provider` and the same bounded
  `error_code` its metric is already labelled with (`classifyPollError`), so a
  refusal can be filtered and correlated rather than only carrying free text.

  The `pkg/auth` device-flow tests now run against a real file-backed audit logger
  and assert on what it wrote, since a disabled logger cannot show a wrong record.
- **High (#152): no login ever got an SSH key, which is the one thing the broker
  exists to hand out.** `Broker.generateSSHKey` files the on-disk key pair under
  the *session* ID, deliberately, so that concurrent sessions for one user do not
  overwrite each other's key — but `KeyManager.SaveKey` validated that argument
  with `validateUsername`, and a 64-character hex session ID is not a POSIX login
  name. Every save was refused, the error was only written to the broker's own
  log, and the login carried on and was audited as `authentication_successful`.
  So a device flow completed, PAM returned success, and `authorized_keys` was
  never touched. Introduced by `2e5522a`'s path-traversal hardening: the hardening
  was right, the validator was simply the wrong one for an argument that is not a
  username.

  The key store is now explicitly keyed by an opaque **key ID**: `validateKeyID`
  (anchored, length-bounded, no dots or separators, so traversal is still
  impossible) replaces `validateUsername` in `SaveKey`/`LoadKey`/`DeleteKey`/
  `GetKeyPath`/`GetPublicKeyPath`, and those parameters are named `keyID` so the
  contract is legible from the signature. `validateUsername` stays where the
  argument really is a username. `KeyInfo` gains a `KeyID`, and its `Username` is
  now recovered from the key's comment instead of being the storage directory
  name — so `oidc-admin keys` no longer prints session IDs in a `USERNAME`
  column, and gains a `SESSION` column to tie a key to the session that owns it.
  A provisioning failure is now also audited (`ssh_key_provisioning_failed`)
  rather than only logged, since that silence is why this survived eleven
  releases.

  Unit tests passed on both sides throughout: each half was self-consistent, and
  the one test that exercised the store end to end used the session ID
  `"sess-poll-test"` — which satisfies the POSIX username pattern by accident.
  The regression gate therefore uses a session ID of the shape the broker really
  mints, and asserts the key reaches both the store and the user's
  `authorized_keys`.
- **Critical (#150): the broker abandoned every device flow on the first poll,
  so no device login could ever complete.** RFC 8628 §3.5 makes
  `authorization_pending` the *normal* answer to every poll before the user
  finishes in the browser, but `PollDeviceAuthorization` returned it wrapped as
  `"token error: authorization_pending"` while `pollDeviceAuthorization`
  compared `err.Error()` against the bare `"authorization_pending"`. The
  comparison never matched, so the pending answer fell through to the deny path:
  audit `device_authorization_failed`, session deleted, goroutine gone —
  typically about five seconds after the verification URL was displayed, leaving
  the user with a code and a session that no longer existed. `slow_down` was
  treated the same way, and the polling interval never grew as the RFC requires.
  The two codes are now sentinel errors (`ErrAuthorizationPending`, `ErrSlowDown`)
  wrapped with `%w` and matched with `errors.Is`, so the pending path continues
  polling, `slow_down` adds 5 s to the interval and resets the ticker, and only
  the device code's own expiry or a genuinely terminal code (`access_denied`,
  `expired_token`, an invalid ID token) ends the flow. The audit message keeps
  its `token error: <code>` shape.

  The bug was invisible to unit tests on either side — the provider returned the
  right code and the loop compared against a plausible string; what went untested
  was the two halves agreeing. So the regression gate is an end-to-end one: see
  **Added** below.

### Added
- **(#129) `test/e2e`, an end-to-end harness: real `sshd`, real PAM stack, real
  `pam_oidc.so`, real broker, and a scripted fake identity provider, in Docker.**
  `make test-e2e` runs it; it needs nothing but Docker — no credentials, no
  network egress, no Keycloak. Every case is an actual SSH login that either
  happens or does not, because the thing under test is what PAM makes of the
  module's return code in the context of a real stack, and that is where every
  serious defect this project has shipped has lived: #120 (`PAM_SUCCESS` returned
  while the user was still deciding, which `auth sufficient` turns into a
  bypass), #140 (a `.so` containing no `pam_sm_*` symbols at all), #150 (every
  device flow abandoned on its first poll). Each of those passed every unit test
  on both sides of the boundary it broke.

  Nine cases: the login waits while nothing is approved (the #120 gate), an
  approval completes it and installs exactly one key, a flow nobody approves is
  refused after the module's whole budget, a provider refusal is terminal, an ID
  token for another user cannot log in as this one (#90), `require_groups` is
  enforced (#92), an `account required` module below `pam_oidc.so` can still
  refuse a login whose auth phase succeeded (#122), a non-root peer is refused on
  the IPC socket, and an absent broker is reported at once rather than after the
  device-flow budget. Verified against a deliberately reintroduced #120: the two
  bypass cases fail, naming it.

  It found #152 and #153 on its first run, both of which had survived eleven
  releases and the whole unit suite.
- `test/e2e/fakeoidc`, the scripted issuer it authenticates against: discovery,
  JWKS, RS256-signed ID tokens with a real `nonce`/`aud`/`iss`, the device
  authorization and token endpoints, and a `/control/*` API so a case can decide
  *when* the user approves, deny, expire, or change which identity the token
  carries. Approving before the broker is really polling would test a race rather
  than a device flow, so `/control/state` reports the poll count.
- A CI job running the harness on `ubuntu-latest`. It builds everything inside
  its own images, so unlike the other jobs it needs neither Go nor PAM headers on
  the runner.
- `internal/testoidc`, an in-process OpenID Connect issuer for tests: discovery,
  JWKS, RS256-signed ID tokens (real signatures, real `aud`/`iss`/`exp`/`nonce`,
  so go-oidc's verifier is exercised rather than bypassed), the device
  authorization endpoint and userinfo. Its point is `Script(...)`, which sets the
  *sequence* of token-endpoint answers — a fake that grants on the first poll
  cannot tell a working client from one that treats `authorization_pending` as
  fatal, which is precisely #150.
- `pkg/auth` tests driving `pollDeviceAuthorization` against that issuer:
  pending-pending-grant reaches an active session with its tokens in the
  encrypted store (this fails on the pre-fix code with the session already
  deleted after one poll), `slow_down` slows the poll rate without ending the
  flow, `access_denied` and `expired_token` stay terminal, the device code's
  expiry bounds the loop, and stopping the broker abandons it. `Broker` gained an
  unexported `pollIntervalUnit` so those tests do not have to wait out RFC 8628's
  5-second interval floor.

### Removed
- **(#129) The Keycloak integration harness, which `test/e2e` replaces and which
  no CI job ran.** `test/integration` (a `package main` behind a build tag that
  `./...` skips), `docker-compose.test.yml`, `test/Dockerfile.integration`,
  `test/config/integration-test.yaml`, `test/keycloak`,
  `scripts/{start,run}-integration-tests.sh` and the `test-projects/ssh-server`
  shell harness are gone, along with the `test-integration` and
  `test-integration-run` make targets. What they promised — a real login through
  a real PAM stack — is what `make test-e2e` now delivers, in a form that runs in
  CI and needs no external identity provider. The QUICK-START section that told a
  reader to bring up the deleted Keycloak compose file points at the harness
  instead.
- `make test-e2e` no longer runs `go test ./test/e2e/...`, which matched no
  packages and therefore passed unconditionally. It runs the harness.

### Security
- Bumped the Go toolchain pin from 1.25.12 to 1.25.13. govulncheck reported four
  called standard-library vulnerabilities against 1.25.12, all fixed in 1.25.13:
  GO-2026-6218 (quadratic `resolvePath` in `net/url`), GO-2026-6090
  (post-handshake message limit in `crypto/tls`), GO-2026-6089
  (`ReadHeaderTimeout` on the unencrypted HTTP/2 check in `net/http`) and
  GO-2026-5972 (asn1 recursion depth). They are reachable from the metrics HTTP
  server, the HTTP audit sink, and the provider TLS setup. Clean afterwards.
- **Critical (#140): every `pam_oidc.so` this project has ever released contains
  no PAM entry points at all.** `nm -D --defined-only bin/pam_oidc.so` finds zero
  `pam_sm_*` symbols, and `readelf -d` shows the module does not even link
  `libpam`. The C implementing the six entry points lived in `pkg/pam`, but cgo
  compiles only the C sources sitting in the directory of the package being
  built, and `cmd/pam-module` — the package built as `c-shared` — does not import
  `pkg/pam`. So the C was never compiled into the artifact. Nothing failed:
  `cgo_bridge.h` supplied valid declarations, nothing referenced `libpam`, and
  the linker's default `-Wl,--as-needed` dropped `-lpam` as unused, leaving a
  build that exits 0 and a module `dlopen()` loads and finds nothing in.
  **The practical effect was total failure, not a bypass** — PAM cannot call a
  function that is not there, so the stack failed rather than admitting anyone,
  and the #120 bypass below was never reachable through the C path on a released
  build. The cost was elsewhere: the module could not authenticate anyone, and
  every C-side fix was absent from the shipped `.so` regardless of what the
  source said. The C bridge now lives in `cmd/pam-module` alongside the package
  that produces the module, and three separate gates check the artifact rather
  than the source — see **Added** below.
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
  no longer hand-copied guesses: each one is checked against the PAM macro of the
  same name in the headers the module is compiled against, by
  `TestPAMResultCodesMatchHeaders` (see **(#141)** under **Added**). The values
  are not portable between Linux-PAM and OpenPAM, so the test is what keeps
  `pkg/pam`'s literals honest.

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
- **(#142)** `.golangci.yml` and `.golangci-version`. There was no lint
  configuration, so the linter set was whatever the installed binary defaulted to
  — decided by the tool version rather than by this repository, which is how a
  contributor on a different version sees different results and how a tool upgrade
  silently adds or drops a check. The standard set (errcheck, govet, ineffassign,
  staticcheck, unused) is now declared explicitly; it changes nothing today, which
  is the point. The version is single-sourced in `.golangci-version`, read by the
  CI Lint job, `test/docker/Dockerfile.verify` and `make lint` — which warns if
  the locally installed version differs, rather than reporting a clean run that
  CI will not reproduce.
- **(#140)** `scripts/verify-pam-module.sh` — the gate that would have caught the
  empty module. It asserts a built `.so` exports all six `pam_sm_*` entry points
  and links `libpam` and `libjson-c`, and it runs everywhere a shipped module is
  produced: `make build-pam`, `make verify-linux`, and the release workflow's
  per-architecture build. A compiler cannot catch a missing entry point — the
  declarations are valid and the symbol is simply never defined — so the only
  check that works is inspecting the artifact.
- **(#140)** `make build-pam` refuses to run outside Linux instead of emitting a
  module with no C in it (`make build` skips it there and builds everything else;
  use `make verify-linux`). `make verify-linux` now also builds the module and
  verifies it, and covers `./cmd/...` in the test sweep — where the cgo tests now
  live.
- **(#141)** `TestPAMResultCodesMatchHeaders` (`cmd/pam-module`) compares every
  `PAMResultCode` in `pkg/pam` against the PAM macro of the same name in the
  headers the module is compiled against, and fails if a value or the set of
  codes drifts. This preserves what #118 established — that the codes are not
  hand-copied guesses — now that `pkg/pam` declares them without cgo.
- **(#141)** A `macOS (no PAM headers)` CI job runs `go build ./...`,
  `go vet ./...` and `go test ./...` on `macos-latest`. The point is what is *not*
  installed: with no `<security/pam_ext.h>` and no json-c, any cgo that escapes
  `cmd/pam-module`'s `//go:build linux` constraint fails CI instead of only
  breaking for contributors on a Mac — which is how the tree came to be
  unbuildable there in the first place.
- **(#141)** `scripts/check-cgo-quarantine.sh` (`make check-cgo`, and a step in
  the `Validate` job) asserts that `cmd/pam-module` is the only package with cgo
  files under `GOOS=linux`, and that no package has any under `GOOS=darwin`. It
  reads the build graph rather than the host, so it gives the same answer on any
  OS with no headers installed, and it names the offending package instead of
  failing with a missing header a hundred lines into a compile. Both halves
  matter: cgo escaping the module breaks the macOS build (#141), and C leaving
  `cmd/pam-module` is exactly what shipped a module with no entry points (#140).
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
- **(#140)** The C bridge moves from `pkg/pam` to `cmd/pam-module`
  (`cgo_bridge.c` → `cgo_bridge_linux.c`, plus `cgo_bridge.h` and the cgo wrappers
  and tests around them). This is the fix, not tidying: the C has to be in the
  package built as `c-shared` for cgo to compile it in. The `_linux` filename
  suffix is how the go tool applies a build constraint to a C file — a build tag
  in a C comment is not honoured.
- **(#141)** `pkg/pam` is now pure Go and builds and tests on any platform. It
  needed cgo for three things, none of which required C: the `PAMResultCode`
  constants (now Go literals, pinned to the real headers by a test in
  `cmd/pam-module`), `LogMessage` (now `log/syslog` to `LOG_AUTHPRIV`, where
  `pam_syslog` was writing anyway), and `C.getpid()` (now `os.Getpid()`). With
  that, `go build ./...` and `go test ./...` work on macOS, and the cgo/PAM
  packages CI has to treat specially are down to one: `cmd/pam-module`. The
  `pam_sm_*` entry points are unaffected — they are C, called by libpam, and stay
  C.
- **(#141)** The `Test` job runs `go vet ./...` and `go test -race ./...` instead
  of two hand-maintained package lists, and installs the PAM headers because
  `./...` now includes `cmd/pam-module`. A list of packages to check is a list of
  packages someone has to remember to extend, and that is the whole mechanism by
  which the PAM code went years without being vetted or tested (#113/#118). The
  `PAM (cgo)` job stays, overlapping with this one on purpose, so a break in the C
  is reported as a cgo failure by name.
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
- **(#141)** `pkg/pam`'s `ConnectToBroker`, `SendAuthRequest`,
  `ReceiveAuthResponse`, `CloseSocket` and `LogPAMMessage`, along with
  `log_pam_message_string` in the C bridge. They were a cgo-wrapped duplicate of
  the socket handling the C module does for itself, referenced only by their own
  tests — the live Go path has gone through `internal/brokerclient` since #121.
  Their tests asserted that a bad file descriptor fails, which is a property of
  the C library, not of this project.
- **(#141) `test/integration/broker_test.go` (748 lines), which had never passed.**
  All three of its top-level tests died in `auth.NewBroker`: the fixture's issuer
  was `mock://test-provider` and OIDC discovery is an HTTP GET, so every run
  ended in `unsupported protocol scheme "mock"`. The subtests behind that failure
  were written against a broker that does not exist either — `key_create` and
  `risk_assess` are not request types the broker implements, several sent two
  requests down one connection when the broker answers one per connection, and
  `sessions_list`/`keys_list` require uid 0. The directory did not even build
  under its own `integration` tag (`package integration` in the test file,
  `package main` in `main.go`), which it now does. Nothing was covered by this
  file: `internal/ipc` exercises the same request surface over real sockets, and
  end-to-end coverage through PAM is what the container harness in #129 is for.
  `make test-integration` now vets the tagged Keycloak harness that
  `docker-compose.test.yml` actually runs, and `make test-integration-run` runs
  it, instead of pointing `go test` at a package with no tests in it.
- **(#141)** The four `cgo_{linux,darwin}.go` files that carried nothing but
  duplicate `#cgo` flag comments. cgo merges `#cgo` directives across a package,
  so the flags are declared once, in `cmd/pam-module/bridge_linux.go`.
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
- **(#142)** An unchecked `f.Close()` in `internal/ipc/peercred_darwin.go`, which
  its Linux twin handles explicitly. It went unnoticed because the file is
  `//go:build darwin` and CI lints on Linux only — a reminder that the platform CI
  runs on decides which code gets checked at all.
- **(#127)** `.gitignore` no longer ignores `*.h`. The cgo bridge headers
  (`cmd/pam-module/cgo_bridge.h`) are source files, so the rule meant a newly added
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

### Fixed
- Published releases carried **empty release notes**. `release.yml` pulled this
  version's CHANGELOG section with an awk range whose end pattern (`^## `) also
  matches the version header that opens the range, so awk closed the range on the
  line that opened it and `head -n -1` deleted the single line it produced. Every
  release up to and including v0.4.2 was published with an empty body. The section
  is now read from its header to the next one and passed as `--notes-file`, and a
  version with no section logs a warning instead of silently publishing nothing.

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
