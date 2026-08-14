#!/usr/bin/env bash
#
# The end-to-end cases. Runs inside the client container as root, one case per
# invocation: cases.sh <case-name>. run-tests.sh drives it and restarts the
# broker in between, so each case starts from a broker with no sessions.
#
# Every case is an SSH login that either happens or does not. That is the whole
# point: the defects this exists to catch (#120, #122, #150) all lived in the
# space between components — a return code PAM interprets differently than the
# module meant, an error string one half formats and the other compares — and
# each of them passed every unit test on both sides.
#
# No `set -e`: a case asserts on failing logins, so a non-zero exit from ssh is
# data, not an error.

set -uo pipefail

CONTROL="http://fakeoidc:8080/control"
SOCKET="/var/run/oidc-auth/broker.sock"
AUDIT_LOG="/harness/audit/audit.log"
MODULE_LOG="/harness/logs/pam.log"
PAM_FILE="/etc/pam.d/sshd"

# Must match timeout= in pam-sshd. The module bounds the whole device flow with
# it, so it is both how long a never-approved login takes to be refused and the
# ceiling a refusal-for-another-reason has to come in under.
LOGIN_TIMEOUT=15

# The broker polls the issuer at RFC 8628's 5-second floor, and the module polls
# the broker at the interval the broker reports (also 5). So a login that is
# approved immediately still takes one or two of those before it completes, and
# nothing here can be asserted to sub-5-second precision.
POLL_INTERVAL=5

failures=0

log()  { printf '    %s\n' "$*"; }
fail() { printf '    FAIL: %s\n' "$*"; failures=$((failures + 1)); }

# ---------------------------------------------------------------------------
# Talking to the fake issuer
# ---------------------------------------------------------------------------

control() { curl -fsS "${CONTROL}/$1"; }

state_field() { control state | jq -r ".$1"; }

# reset_state puts the issuer back to "the user has not approved anything yet",
# with an identity that matches the local account the case logs in as, and
# records where the audit log has got to so later assertions only see this
# case's events.
reset_state() {
    local username="${1:-alice}"
    control reset >/dev/null || { fail "could not reach the fake issuer's control API"; return 1; }
    control "identity?username=${username}" >/dev/null
    AUDIT_MARK=$(wc -l <"${AUDIT_LOG}" 2>/dev/null || echo 0)
    MODULE_MARK=$(wc -l <"${MODULE_LOG}" 2>/dev/null || echo 0)
    log "issuer reset: pending, identity ${username}"
}

# wait_for_polls waits until the issuer has been polled at least n times, which
# is how a case knows the broker really is in the flow. Approving before that
# would test a race rather than a device flow.
wait_for_polls() {
    local want="$1" deadline=$((SECONDS + ${2:-30})) polls
    while [[ "${SECONDS}" -lt "${deadline}" ]]; do
        polls="$(state_field polls)"
        if [[ "${polls}" =~ ^[0-9]+$ ]] && [[ "${polls}" -ge "${want}" ]]; then
            log "issuer has been polled ${polls} time(s)"
            return 0
        fi
        sleep 1
    done
    fail "the issuer was never polled ${want} time(s): the broker did not start the device flow"
    return 1
}

# ---------------------------------------------------------------------------
# Logging in
# ---------------------------------------------------------------------------

# ssh_login runs one login attempt. Only keyboard-interactive is offered, so a
# refusal cannot be papered over by another method, and the outer timeout is a
# backstop: a login that hangs past every deadline in the system is a failure,
# not a reason to wedge the suite.
ssh_login() {
    local user="$1"
    timeout 90 ssh \
        -F /dev/null \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=keyboard-interactive \
        -o PubkeyAuthentication=no \
        -o PasswordAuthentication=no \
        -o NumberOfPasswordPrompts=1 \
        -o ConnectTimeout=5 \
        "${user}@127.0.0.1" 'echo LOGIN_OK' </dev/null 2>&1
}

# attempt_login runs a login to completion, and sets:
#   LOGIN_EXIT     ssh's exit status (0 only if the login succeeded)
#   LOGIN_ELAPSED  wall-clock seconds it took
#   LOGIN_OUTPUT   everything ssh printed, including what PAM told the user
attempt_login() {
    local user="$1" start="${SECONDS}"
    LOGIN_OUTPUT="$(ssh_login "${user}")"
    LOGIN_EXIT=$?
    LOGIN_ELAPSED=$((SECONDS - start))
    log "login as ${user}: exit ${LOGIN_EXIT} after ${LOGIN_ELAPSED}s"
}

# start_login runs a login in the background, for the cases that need to look at
# the system while the user is still deciding.
start_login() {
    local user="$1"
    LOGIN_FILE="$(mktemp)"
    LOGIN_START="${SECONDS}"
    ssh_login "${user}" >"${LOGIN_FILE}" 2>&1 &
    LOGIN_PID=$!
    log "login as ${user} started in the background (pid ${LOGIN_PID})"
}

# reap_login waits for a background login and fills in the same variables
# attempt_login sets.
reap_login() {
    wait "${LOGIN_PID}"
    LOGIN_EXIT=$?
    LOGIN_ELAPSED=$((SECONDS - LOGIN_START))
    LOGIN_OUTPUT="$(cat "${LOGIN_FILE}")"
    rm -f "${LOGIN_FILE}"
    log "background login finished: exit ${LOGIN_EXIT} after ${LOGIN_ELAPSED}s"
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

expect_login_ok() {
    if [[ "${LOGIN_EXIT}" -ne 0 ]]; then
        fail "expected the login to succeed, got exit ${LOGIN_EXIT}"
        printf '%s\n' "${LOGIN_OUTPUT}" | sed 's/^/      ssh: /'
        return 1
    fi
    if ! grep -q 'LOGIN_OK' <<<"${LOGIN_OUTPUT}"; then
        fail "ssh exited 0 but the remote command did not run"
        return 1
    fi
    log "login succeeded"
}

expect_login_refused() {
    if [[ "${LOGIN_EXIT}" -eq 0 ]]; then
        fail "expected the login to be REFUSED, but it succeeded — $*"
        printf '%s\n' "${LOGIN_OUTPUT}" | sed 's/^/      ssh: /'
        return 1
    fi
    log "login refused, as required"
}

expect_elapsed_at_least() {
    if [[ "${LOGIN_ELAPSED}" -lt "$1" ]]; then
        fail "the login finished after ${LOGIN_ELAPSED}s, expected at least $1s: $2"
    fi
}

expect_elapsed_below() {
    if [[ "${LOGIN_ELAPSED}" -ge "$1" ]]; then
        fail "the login took ${LOGIN_ELAPSED}s, expected less than $1s: $2"
    fi
}

audit_since_mark() { tail -n "+$((AUDIT_MARK + 1))" "${AUDIT_LOG}" 2>/dev/null; }

module_log_since_mark() { tail -n "+$((MODULE_MARK + 1))" "${MODULE_LOG}" 2>/dev/null; }

# expect_audit waits for a pattern in the events this case produced. The audit
# logger writes through a buffered channel, so the record can land a moment after
# the login it describes.
expect_audit() {
    local pattern="$1" deadline=$((SECONDS + 15))
    while [[ "${SECONDS}" -lt "${deadline}" ]]; do
        if audit_since_mark | grep -q "${pattern}"; then
            log "audit log contains ${pattern}"
            return 0
        fi
        sleep 1
    done
    fail "the broker's audit log never recorded ${pattern}"
    audit_since_mark | tail -5 | sed 's/^/      audit: /'
    return 1
}

expect_no_audit() {
    sleep 2 # give a record that should not exist time to show up
    if audit_since_mark | grep -q "$1"; then
        fail "the audit log contains $1, which this case must not produce"
        audit_since_mark | grep "$1" | sed 's/^/      audit: /'
    else
        log "audit log does not contain $1, as required"
    fi
}

expect_module_log() {
    if module_log_since_mark | grep -q "$1"; then
        log "the module logged: $1"
    else
        fail "the module never logged $1"
        module_log_since_mark | grep -i 'pam_oidc' | tail -5 | sed 's/^/      syslog: /'
    fi
}

expect_no_module_log() {
    if module_log_since_mark | grep -q "$1"; then
        fail "the module logged $1, which this case must not produce"
        module_log_since_mark | grep "$1" | sed 's/^/      syslog: /'
    else
        log "the module did not log $1, as required"
    fi
}

expect_oidc_key_for() {
    local user="$1" keys="/home/$1/.ssh/authorized_keys"
    if [[ ! -f "${keys}" ]]; then
        fail "${keys} does not exist: the broker did not install a login key"
        return 1
    fi
    local count
    count="$(grep -c '@oidc-pam-' "${keys}")"
    if [[ "${count}" -ne 1 ]]; then
        fail "${keys} has ${count} @oidc-pam- key(s), expected exactly 1"
        sed 's/^/      authorized_keys: /' "${keys}"
        return 1
    fi
    log "${user} has exactly one @oidc-pam- key in authorized_keys"
}

expect_no_oidc_key_for() {
    local keys="/home/$1/.ssh/authorized_keys"
    if [[ -f "${keys}" ]] && grep -q '@oidc-pam-' "${keys}"; then
        fail "${keys} gained an @oidc-pam- key for a login that was refused"
        sed 's/^/      authorized_keys: /' "${keys}"
    else
        log "$1 has no @oidc-pam- key, as required"
    fi
}

# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

# #120, the bypass itself: while the user has not approved anything, the login
# must still be waiting. It must not have returned success, and no session may
# have been created.
#
# This is the case that fails against the unfixed module: it returned PAM_SUCCESS
# as soon as the broker said requires_device, so the login was already over —
# granted — by the time the issuer had been polled once.
case_waits_while_pending() {
    reset_state alice || return 1

    start_login alice
    wait_for_polls 1 30 || { kill "${LOGIN_PID}" 2>/dev/null; return 1; }

    # Give a bypass every chance to show itself: the broker has polled, so the
    # module has had a full poll interval in which it could wrongly have
    # succeeded.
    sleep "${POLL_INTERVAL}"

    if ! kill -0 "${LOGIN_PID}" 2>/dev/null; then
        reap_login
        fail "the login finished after ${LOGIN_ELAPSED}s while the user had approved nothing (exit ${LOGIN_EXIT})"
        if [[ "${LOGIN_EXIT}" -eq 0 ]]; then
            fail "and it SUCCEEDED: this is the #120 device-flow bypass"
        fi
        printf '%s\n' "${LOGIN_OUTPUT}" | sed 's/^/      ssh: /'
        return 1
    fi
    log "the login is still waiting, as required"
    expect_no_oidc_key_for alice
    expect_no_audit authentication_successful

    # Let it finish rather than leaving an SSH connection and a broker goroutine
    # behind for the next case.
    #
    # Whether it now succeeds is deliberately not asserted. Everything above —
    # waiting for the first poll, then a full poll interval, then looking at the
    # filesystem and the audit log — has already spent most of the module's
    # device-flow budget, so an approval this late can legitimately land after the
    # deadline. That an approval grants the login is case_approved_login's claim,
    # and it approves as soon as the flow is up.
    control approve >/dev/null
    reap_login
}

# The happy path, end to end: approve while the login is waiting and it must
# complete, install exactly one login key, and be recorded.
case_approved_login() {
    reset_state alice || return 1

    start_login alice
    wait_for_polls 1 30 || { kill "${LOGIN_PID}" 2>/dev/null; return 1; }

    control approve >/dev/null
    reap_login

    expect_login_ok || return 1
    expect_oidc_key_for alice
    expect_audit authentication_successful

    # The user has to be told where to go, or the device flow is unusable by a
    # human even when it works.
    if grep -q 'fakeoidc:8443/activate\|WDJB-MJHT' <<<"${LOGIN_OUTPUT}"; then
        log "the verification URL or user code reached the client"
    else
        fail "the client was never shown the verification URL or user code"
        printf '%s\n' "${LOGIN_OUTPUT}" | sed 's/^/      ssh: /'
    fi
}

# #169: which end of the connection each field describes. The module used to send
# PAM_RHOST as target_host and no source_ip at all, so the broker saw every login
# as arriving from nowhere and going to the client — and require_private_network,
# which is evaluated against source_ip, refused every login on the host.
#
# sshd and the broker are in this container, so the login comes from 127.0.0.1 and
# arrives at this container's hostname. Those are different strings, which is what
# makes the inversion visible here and not in either half's own tests.
case_source_ip_is_the_client_address() {
    reset_state alice || return 1

    start_login alice
    wait_for_polls 1 30 || { kill "${LOGIN_PID}" 2>/dev/null; return 1; }
    control approve >/dev/null
    reap_login

    expect_login_ok || return 1

    # pam-sshd sets debug, so the module logs the request it sent. json-c prints a
    # space after the colon; the patterns tolerate either.
    expect_module_log '"source_ip": *"127.0.0.1"'
    expect_module_log "\"target_host\": *\"$(hostname)\""
    expect_no_module_log '"target_host": *"127.0.0.1"'

    # And the address survives the trip: an audit record that does not say where a
    # login came from cannot be used to investigate one.
    expect_audit 'authentication_successful.*"source_ip":"127.0.0.1"'
}

# #120's other half: a device flow nobody ever approves must end in a refusal,
# not in a grant and not in a hang. The module's own timeout= is what bounds it.
case_never_approved() {
    reset_state alice || return 1

    attempt_login alice

    expect_login_refused "the user approved nothing"
    expect_elapsed_at_least "${LOGIN_TIMEOUT}" \
        "it must wait for the whole device-flow budget before giving up, not fail early for some unrelated reason"
    expect_no_oidc_key_for alice
    expect_no_audit authentication_successful
}

# A refusal at the identity provider is terminal (RFC 8628): the broker must stop
# polling and drop the session, and the login must be refused *because of that
# denial* rather than by eventually running out of time — a login that merely
# timed out looks identical from the outside.
#
# So the evidence is what the two components recorded, not the clock. The module
# logs a refusal and a timeout differently, and asserting on that is both exact
# and honest: wall-clock elapsed here also contains the SSH handshake and sshd's
# post-failure delay, several seconds that sit outside the module's budget and
# have nothing to do with how promptly the denial was noticed.
case_denied_by_provider() {
    reset_state alice || return 1

    control deny >/dev/null
    attempt_login alice

    expect_login_refused "the identity provider answered access_denied"
    expect_audit device_authorization_failed
    expect_module_log 'Broker refused authentication'
    expect_no_module_log 'Device authorization not completed within'
    expect_no_oidc_key_for alice
    expect_no_audit authentication_successful
}

# #90: the OIDC identity must be bound to the local account being logged into.
# An ID token for carol cannot log in as alice, however valid it is.
case_identity_mismatch() {
    reset_state carol || return 1

    control approve >/dev/null
    attempt_login alice

    expect_login_refused "the ID token says carol, the login is for alice"
    expect_audit IDENTITY_MISMATCH
    expect_no_oidc_key_for alice
}

# #159: no OIDC identity binds to a privileged local account. svcacct has uid
# 400, and the identity here matches it *exactly* — same preferred_username, in
# the required group, approved by the user. The only thing wrong with this login
# is the account it wants to be, which is the whole point: this is the check that
# still holds when username_claim or allowed_email_domains is misconfigured.
#
# Deliberately not root: sshd_config.d/oidc-pam.conf sets PermitRootLogin no, so
# `ssh root@` never reaches PAM and the case would pass without testing anything.
# A uid < 1000 account that sshd will accept is what exercises the guard.
#
# svcacct has to exist in *both* images at the same uid. The guard resolves the
# account in the broker, so with the account only in the client image the broker
# sees no such user, allows the binding, and this case passes the login it is
# supposed to refuse. Dockerfile.broker creates it for that reason.
case_privileged_account_refused() {
    reset_state svcacct || return 1

    control approve >/dev/null
    attempt_login svcacct

    expect_login_refused "svcacct is uid 400, below the privileged threshold"
    expect_audit PRIVILEGED_ACCOUNT_DENIED
    expect_no_oidc_key_for svcacct
}

# #159: the local part of an email-shaped claim does not bind on its own. The
# identity is alice@example.org and the login is for alice; broker.yaml does not
# set username_claim_strip_domain, so this is refused. Before #159 the local part
# matched unconditionally, which is what let root@anything log in as root.
case_email_local_part_refused() {
    reset_state alice || return 1
    control 'identity?username=alice@example.org' >/dev/null

    control approve >/dev/null
    attempt_login alice

    expect_login_refused "alice@example.org must not bind to local alice without the opt-in"
    expect_audit IDENTITY_MISMATCH
    expect_no_oidc_key_for alice
}

# #92: require_groups is enforced. Same user, same approval, no group.
case_group_denied() {
    reset_state alice || return 1
    control 'identity?username=alice&groups=' >/dev/null

    control approve >/dev/null
    attempt_login alice

    expect_login_refused "alice is in none of the required groups"
    expect_audit GROUP_DENIED
    expect_no_oidc_key_for alice
}

# #122: the account phase still decides. The auth phase succeeds here — the user
# approves and the broker is happy — and the login must be refused anyway
# because an account module below pam_oidc.so says no.
case_account_stack_denies() {
    reset_state alice || return 1

    # run-tests.sh puts the default stack back before every case, so an early
    # return here cannot leak this one into the next case.
    cp /harness/pam-sshd-account-deny "${PAM_FILE}"

    start_login alice
    wait_for_polls 1 30 || { kill "${LOGIN_PID}" 2>/dev/null; return 1; }
    control approve >/dev/null
    reap_login
    cp /harness/pam-sshd "${PAM_FILE}"

    expect_login_refused "an 'account required' module refused, whatever the auth phase decided"
    # The auth phase really did succeed, or this case would prove nothing: the
    # broker completed the flow and recorded it.
    expect_audit authentication_successful
}

# The IPC socket is root-only, enforced by the broker rather than by file
# permissions alone (broker.yaml deliberately makes the socket world-writable so
# that this is what gets tested).
#
# Two probes, because of #154. The broker closes the connection with the peer's
# request still unread, and Linux discards a queued response when a socket is
# closed with unread data — so whether a non-root peer that *sends* a request gets
# its refusal back is a race with the close, and has been observed both ways (on
# this machine: nothing at all; on the CI runner: the refusal). A peer that
# connects and sends nothing always receives it.
#
# So the two probes assert different things. The silent one pins the refusal and
# its code, which is a real guarantee. The request one asserts only that the
# request was not *served*, which holds however the race falls.
#
# The code is PERMISSION_DENIED, not PEER_AUTH_DENIED: two peer checks run in
# sequence and the unconditional one always answers first, which is the other half
# of #154. This asserts what the broker actually sends today, so the case fails
# loudly when that is fixed rather than quietly passing on a changed guarantee.
case_nonroot_ipc_rejected() {
    reset_state alice || return 1

    local refusal
    refusal="$(runuser -u alice -- \
        bash -c "timeout 5 nc -U '${SOCKET}' </dev/null" 2>&1)"
    log "broker answered a silent non-root peer: ${refusal:-<nothing>}"
    if grep -q 'PERMISSION_DENIED' <<<"${refusal}"; then
        log "the broker refused a non-root peer"
    else
        fail "a non-root process was not refused with PERMISSION_DENIED"
    fi

    local request='{"type":"authenticate","user_id":"alice","login_type":"ssh","target_host":"client"}'
    local response
    response="$(runuser -u alice -- \
        bash -c "printf '%s' '${request}' | timeout 5 nc -U '${SOCKET}'" 2>&1)"
    log "broker answered a non-root authenticate request: ${response:-<nothing>}"
    if grep -q '"success":true' <<<"${response}"; then
        fail "the broker started an authentication for a non-root process"
    fi

    # And nothing was started on its behalf: a served request would have begun a
    # device flow, which polls the issuer within a few seconds.
    sleep "${POLL_INTERVAL}"
    local polls
    polls="$(state_field polls)"
    if [[ "${polls}" != "0" ]]; then
        fail "the issuer was polled ${polls} time(s): the broker began a device flow for a non-root peer"
    else
        log "the issuer was never polled, as required"
    fi
    expect_no_audit authentication_successful
}

# #160: the request budget is per account, not per host. It used to be keyed on
# the peer's uid, which is 0 for every caller on a root-only socket, so one bucket
# governed the whole machine: an unauthenticated client opening SSH connections to
# any syntactically valid username emptied it, and every login on the host was then
# refused with PAM_MAXTRIES — with no password fallback in the shipped stack.
#
# The requests here name bob and go straight to the socket, because that is the
# cheap version of the attack: no SSH, no credentials, nothing but a username.
#
# This runs after case_nonroot_ipc_rejected on purpose. It leaves pending device
# flows behind, and that case asserts the issuer has not been polled at all.
case_rate_limit_is_per_account() {
    reset_state alice || return 1

    # Must match max_requests_per_minute in broker.yaml, which is deliberately low
    # so this case is quick. One request over the budget, so the last is refused —
    # which is also what makes the assertion below fail loudly rather than quietly
    # pass if that figure changes.
    local budget=12
    local request='{"type":"authenticate","user_id":"bob","login_type":"ssh","target_host":"client"}'
    local response="" i
    for ((i = 0; i <= budget; i++)); do
        response="$(printf '%s' "${request}" | timeout 5 nc -U "${SOCKET}")"
    done

    if grep -q 'RATE_LIMIT_EXCEEDED' <<<"${response}"; then
        log "bob's budget is spent after $((budget + 1)) requests naming him"
    else
        fail "$((budget + 1)) requests naming bob did not exhaust his budget: ${response:-<nothing>}"
        return 1
    fi

    # And alice, who was never named, logs in normally. This is the assertion the
    # unfixed broker fails: her authenticate drew on the same bucket bob's requests
    # had just emptied.
    #
    # The approval also completes bob's pending flows, which are refused as
    # IDENTITY_MISMATCH — the identity is alice's — and so write no keys.
    control approve >/dev/null
    attempt_login alice

    expect_login_ok || return 1
    expect_audit authentication_successful
    expect_oidc_key_for alice
}

# #161: a user holding a lock in their own home must not affect the broker.
#
# The broker used to serialize its authorized_keys writes on
# ~/.ssh/authorized_keys.lock — a path inside the home of the account it was
# protecting — with a blocking flock. So `flock ~/.ssh/authorized_keys.lock -c
# 'sleep infinity'`, which any user can run, blocked the broker's next write to
# that file forever: the login below never finished, and worse, the broker's single
# cleanup goroutine stopped expiring sessions and revoking keys for every account
# on the host.
#
# The lock now lives in /var/lib/oidc-pam/locks inside the broker, which the user
# cannot reach, and every acquisition is bounded. So the file alice holds here is
# just a file, and her login is ordinary.
#
# The client and broker containers share /home, so alice's flock here really does
# contend with anything the broker takes on the same path — which is what makes
# this a regression test rather than a demonstration.
case_home_lock_does_not_block_login() {
    reset_state alice || return 1

    if ! command -v flock >/dev/null; then
        fail "flock is not installed in the client image; this case cannot hold a lock"
        return 1
    fi

    # On a real host a user owns their own ~/.ssh, and that ownership is exactly
    # what made the old lock path reachable. Assert it here rather than assume it:
    # if an earlier case already logged alice in, the broker created ~/.ssh as root
    # (a separate problem, #171), alice could not create the lock file at all, and
    # this case would quietly hold nothing.
    install -d -o alice -g alice -m 700 /home/alice/.ssh || {
        fail "could not give alice ownership of her own .ssh"
        return 1
    }

    # `exec sleep` so the process that ends up holding fd 9 — and therefore the
    # lock — is the one whose pid lands in the file, which is what makes the
    # cleanup below able to release it. A flock started as `flock -c "sleep ..."`
    # passes the fd to a child, so killing flock would not release anything.
    local pidfile=/tmp/home-lock-holder.pid
    rm -f "${pidfile}"
    su alice -c "mkdir -p ~/.ssh && chmod 700 ~/.ssh \
        && exec 9>~/.ssh/authorized_keys.lock && flock -x 9 \
        && echo \$\$ >${pidfile} && exec sleep 120" &
    # shellcheck disable=SC2064
    trap "[[ -f ${pidfile} ]] && kill \$(cat ${pidfile}) 2>/dev/null; rm -f ${pidfile}" RETURN

    local deadline=$((SECONDS + 15))
    while [[ ! -s "${pidfile}" && "${SECONDS}" -lt "${deadline}" ]]; do sleep 1; done

    # Confirm the lock is really held: a case that silently failed to take it would
    # pass while proving nothing, which is the failure mode this harness keeps
    # finding.
    if flock -n -x /home/alice/.ssh/authorized_keys.lock -c true 2>/dev/null; then
        fail "alice's lock is not held; this case would pass without testing anything"
        return 1
    fi
    log "alice is holding /home/alice/.ssh/authorized_keys.lock (pid $(cat "${pidfile}"))"

    control approve >/dev/null
    attempt_login alice

    # A successful login is the whole assertion. Against the old code the broker
    # blocked inside AddPublicKey before it could mark the session active, so the
    # module polled until its own timeout and the login was refused — a lock in
    # alice's home denied alice her own login, and everyone else's cleanup.
    expect_login_ok || return 1
    expect_audit authentication_successful
    expect_oidc_key_for alice
}

# #162: a long verification URI must not break the login.
#
# The URI reaches the module three times over — as device_url, as text in the
# instructions, and as QR art whose size grows with it — and the module reads the
# whole response into a fixed buffer. At 8 KiB, with the art also serialized into a
# separate qr_code field, a URI of a few hundred bytes pushed an ordinary device
# response past the buffer; what arrived was a truncated prefix, json-c refused it,
# and *every* login on the host was refused with nothing in syslog but "Failed to
# parse broker response" and a PAM result indistinguishable from a broker that was
# not running.
#
# Every provider in the wild hands out a URI of around 30 bytes, which is why
# neither the unit tests nor this harness caught it. So the issuer is asked for a
# long one here, and the assertion is simply that the login works — plus the two
# things that say *why* it worked: the URL still reached the user, and the module
# never had to fall back on a parse failure.
case_long_verification_uri() {
    reset_state alice || return 1

    # 400 bytes of padding: comfortably over the old 8 KiB buffer once rendered as
    # QR art, and within the 512-byte cap the broker now enforces on what a provider
    # may return (validateDeviceAuthLengths, pkg/auth/device_flow.go) — so this is a
    # login the broker must complete, not one it should reject.
    control 'verification-uri?pad=400' >/dev/null
    if [[ "$(state_field uri_padding)" != "400" ]]; then
        fail "the issuer did not take the verification-uri padding; this case would prove nothing"
        return 1
    fi

    start_login alice
    wait_for_polls 1 30 || { kill "${LOGIN_PID}" 2>/dev/null; return 1; }

    control approve >/dev/null
    reap_login

    expect_login_ok || return 1
    expect_oidc_key_for alice
    expect_audit authentication_successful

    # The padded URL itself has to have reached the client: a response that quietly
    # dropped the instructions would pass everything above while leaving a real user
    # with nowhere to go.
    if grep -q 'fakeoidc:8443/activate?p=pppp' <<<"${LOGIN_OUTPUT}"; then
        log "the padded verification URL reached the client"
    else
        fail "the client was never shown the padded verification URL"
        printf '%s\n' "${LOGIN_OUTPUT}" | sed 's/^/      ssh: /'
    fi

    # The #162 symptoms. The first is what a truncated response looks like from the
    # module; the second is the module refusing a response too big for its buffer,
    # which the broker must have prevented by degrading the response instead.
    expect_no_module_log 'Failed to parse broker response'
    expect_no_module_log 'does not fit this module'
}

# With no broker there is no opinion to be had: the module must report that it
# could not reach one (PAM_AUTHINFO_UNAVAIL) and the login must be refused, at
# once rather than after the device-flow budget.
#
# run-tests.sh stops the broker before running this, and it runs last.
case_broker_down() {
    if [[ -S "${SOCKET}" ]]; then
        fail "the broker socket still exists; run-tests.sh must stop the broker before this case"
        return 1
    fi
    MODULE_MARK=$(wc -l <"${MODULE_LOG}" 2>/dev/null || echo 0)
    AUDIT_MARK=$(wc -l <"${AUDIT_LOG}" 2>/dev/null || echo 0)

    attempt_login alice

    expect_login_refused "there is no broker to authenticate against"
    expect_elapsed_below "${LOGIN_TIMEOUT}" \
        "an unreachable broker is known immediately; there is nothing to wait for"
    expect_module_log 'Failed to connect to'
}

# ---------------------------------------------------------------------------

CASES=(
    waits_while_pending
    approved_login
    source_ip_is_the_client_address
    long_verification_uri
    never_approved
    denied_by_provider
    identity_mismatch
    privileged_account_refused
    email_local_part_refused
    group_denied
    account_stack_denies
    nonroot_ipc_rejected
    rate_limit_is_per_account
    home_lock_does_not_block_login
    broker_down
)

# CASES is ordered deliberately (simplest flow first), so it is written out
# rather than derived. That means it can fall out of step with the functions
# actually defined, and a case missing from it is silently never run — which is
# exactly the kind of gap this harness exists to catch. So check.
check_cases_are_registered() {
    local fn name missing=()
    for fn in $(compgen -A function case_); do
        name="${fn#case_}"
        # shellcheck disable=SC2076
        if [[ ! " ${CASES[*]} " =~ " ${name} " ]]; then
            missing+=("${name}")
        fi
    done
    if [[ "${#missing[@]}" -ne 0 ]]; then
        echo "cases.sh: defined but not in CASES, so never run: ${missing[*]}" >&2
        return 1
    fi
}

if [[ "${1:-}" == "--list" ]]; then
    check_cases_are_registered || exit 2
    printf '%s\n' "${CASES[@]}"
    exit 0
fi

name="${1:-}"
if [[ -z "${name}" ]]; then
    echo "usage: cases.sh <case-name>|--list" >&2
    exit 2
fi
if ! declare -F "case_${name}" >/dev/null; then
    echo "cases.sh: unknown case ${name}" >&2
    exit 2
fi

"case_${name}"

if [[ "${failures}" -ne 0 ]]; then
    echo "    ${failures} assertion(s) failed in ${name}"
    exit 1
fi
exit 0
