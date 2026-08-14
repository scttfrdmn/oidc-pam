# End-to-end harness

Real `sshd`, real PAM stack, real `pam_oidc.so`, real broker, a scripted fake
identity provider. Every case is an actual SSH login that either happens or does
not.

```bash
make test-e2e          # or: ./test/e2e/run-tests.sh
```

Needs Docker with the compose plugin. No credentials, no network egress, no
Keycloak.

## Why this exists

The defects this project has shipped were not defects in either half of a
boundary — they were two halves disagreeing, with unit tests passing on both
sides because each half was self-consistent:

- **#120** — the broker returns `success: true` *together with*
  `requires_device: true` when it *starts* a device flow, and the module checked
  `success` first. `auth sufficient pam_oidc.so` then granted the login before
  the user had visited the verification URL. Both halves were individually
  reasonable.
- **#140** — the C implementing the six `pam_sm_*` entry points was never
  compiled into the shipped `.so` at all. The build exited 0 for eleven releases.
- **#150** — the provider reported a pending authorization as
  `"token error: authorization_pending"`; the poll loop compared against
  `"authorization_pending"`. Every device flow was abandoned on its first poll.
- **#152** — found by the first run of this harness. The broker files login keys
  under the session ID; the key store validated that ID as a POSIX username, so
  every save failed, and the login succeeded anyway with no key installed.
- **#153** — also found here. Every successful login was audited without the
  identity it had authenticated.

Nothing short of a login through PAM catches this class of bug, because the thing
under test is what PAM makes of the module's return code in the context of a real
stack.

## Layout

| File | What it is |
| --- | --- |
| `run-tests.sh` | The driver: builds, brings the stack up, runs each case with a freshly restarted broker, tears down. |
| `cases.sh` | The cases and their assertions. Runs *inside* the client container, one case per invocation. |
| `fakeoidc/` | The scripted identity provider (discovery, JWKS, RS256 ID tokens, device + token endpoints) plus a `/control/*` API to drive it. |
| `docker-compose.yml` | Three services. The split is the trust boundary. |
| `Dockerfile.broker` | The server side: broker + `fakeoidc`. |
| `Dockerfile.client` | The only place cgo, `pam_oidc.so` and PAM exist. |
| `pam-sshd` | The PAM stack under test. |
| `pam-sshd-account-deny` | The same, plus an `account required` module that refuses — for the #122 case. |
| `broker.yaml` | Broker config. Deliberately makes the IPC socket world-writable, so the peer check is what gets tested rather than the file mode. |

The broker's Unix socket, `/home` and the audit log are shared volumes, so a case
can assert on the `authorized_keys` file the broker wrote and the event it
recorded — not only on what `ssh` did.

## The cases

| Case | Claim |
| --- | --- |
| `waits_while_pending` | **#120.** While nothing is approved, the login is still *waiting*: not granted, no key, no success event. |
| `approved_login` | The happy path. Approve mid-flow → the login completes, exactly one `@oidc-pam-` key is installed, the event is recorded, and the verification URL reached the client. |
| `never_approved` | A flow nobody approves ends in refusal after the module's whole budget — not a grant, not a hang. |
| `denied_by_provider` | A provider refusal is terminal (RFC 8628) and the login is refused *because of it* — asserted from the module log and audit trail, not the clock. |
| `identity_mismatch` | **#90.** An ID token for `carol` cannot log in as `alice`, however valid it is. |
| `group_denied` | **#92.** `require_groups` is enforced. |
| `account_stack_denies` | **#122.** The account phase still decides: the auth phase genuinely succeeds here and the login is refused anyway. |
| `nonroot_ipc_rejected` | The IPC socket is root-only by broker decision, not by file mode. |
| `broker_down` | No broker → refused at once with `PAM_AUTHINFO_UNAVAIL`, not after the device-flow budget. |

Order matters only for `broker_down`, which runs last because it stops the
broker.

## Working on it

```bash
CASES="approved_login" ./test/e2e/run-tests.sh   # one case
NO_BUILD=1 ./test/e2e/run-tests.sh               # reuse the built images
KEEP=1 ./test/e2e/run-tests.sh                   # leave the stack up afterwards
```

With `KEEP=1` the stack stays up, so you can drive it by hand:

```bash
cd test/e2e
docker compose exec -T client /harness/cases.sh approved_login
docker compose exec client bash
curl -fsS http://fakeoidc:8080/control/state | jq   # from inside the client
docker compose down -v
```

`/control/` takes `reset`, `pending`, `approve`, `deny`, `expire`,
`identity?username=…&groups=…` and `state`. `state` reports the poll count, which
is how a case knows the broker really is in the flow rather than about to be.

A failing case dumps the fake issuer's log, the broker's log, sshd's log, the
module's syslog and the audit log.

## Writing a case

Add `case_<name>()` to `cases.sh` and its name to the `CASES` array. The
assertion helpers (`expect_login_ok`, `expect_login_refused`, `expect_audit`,
`expect_no_audit`, `expect_module_log`, `expect_no_module_log`,
`expect_oidc_key_for`, `expect_no_oidc_key_for`) all report through `fail`, so a
case reports every problem it found rather than only the first.

Two things worth knowing before writing an assertion:

- **Don't assert wall-clock timings tighter than ~5 s.** The broker polls the
  issuer at RFC 8628's floor and the module polls the broker at the interval the
  broker reports, so an immediately-approved login still takes one or two of
  those. Elapsed time also includes the SSH handshake and sshd's post-failure
  delay, which are outside the module's budget. Assert on what the module logged
  instead — it distinguishes "timed out" from "was refused" precisely.
- **Watch what the preamble spends.** The module bounds the whole device flow
  with `timeout=` in `pam-sshd`; a case that waits and pokes around before
  approving may have used most of it, so a grant is no longer guaranteed. Keep
  the "an approval grants the login" claim in a case that approves promptly.
