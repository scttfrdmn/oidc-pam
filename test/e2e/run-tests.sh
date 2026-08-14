#!/usr/bin/env bash
#
# Runs the end-to-end harness: builds the images from the working tree, brings up
# the fake identity provider, the broker and an sshd with pam_oidc.so, then runs
# each case in test/e2e/cases.sh and tears everything down.
#
# `make test-e2e` is this script. It needs docker with the compose plugin and
# nothing else — no credentials, no network egress, no Keycloak.
#
# Environment:
#   KEEP=1          leave the stack running afterwards (for poking at it)
#   CASES="a b"     run only these cases
#   NO_BUILD=1      reuse the images already built

set -uo pipefail

cd "$(dirname "$0")" || exit 1

COMPOSE=(docker compose -f docker-compose.yml)
SOCKET=/var/run/oidc-auth/broker.sock

say() { printf '\n==> %s\n' "$*"; }

dump_logs() {
    say "fakeoidc log"
    "${COMPOSE[@]}" logs --no-color --tail=60 fakeoidc 2>&1 | sed 's/^/  /'
    say "broker log"
    "${COMPOSE[@]}" logs --no-color --tail=120 broker 2>&1 | sed 's/^/  /'
    say "sshd log"
    "${COMPOSE[@]}" logs --no-color --tail=60 client 2>&1 | sed 's/^/  /'
    say "pam_oidc syslog"
    "${COMPOSE[@]}" exec -T client tail -n 60 /harness/logs/pam.log 2>&1 | sed 's/^/  /'
    say "broker audit log"
    "${COMPOSE[@]}" exec -T client tail -n 30 /harness/audit/audit.log 2>&1 | sed 's/^/  /'
}

teardown() {
    if [[ "${KEEP:-0}" == "1" ]]; then
        say "KEEP=1: leaving the stack up (docker compose -f test/e2e/docker-compose.yml down -v to remove it)"
        return
    fi
    say "tearing down"
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1
}
trap teardown EXIT

# reset_homes takes the login keys away again. /home is a volume shared with the
# broker, so a key an earlier case had installed outlives that case — and then a
# later case asserting that a *refused* login installed no key would be reading
# the previous case's key. Before #152 was fixed no key was ever written, so this
# went unnoticed: every such assertion passed vacuously.
reset_homes() {
    "${COMPOSE[@]}" exec -T client bash -c 'rm -f /home/*/.ssh/authorized_keys'
}

# wait_for_socket blocks until the client container can see the broker's socket.
# The socket is a volume shared between two containers, so "the broker started"
# and "the client can reach it" are not the same event.
wait_for_socket() {
    local deadline=$((SECONDS + 60))
    while [[ "${SECONDS}" -lt "${deadline}" ]]; do
        if "${COMPOSE[@]}" exec -T client test -S "${SOCKET}" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "the broker socket never appeared at ${SOCKET}" >&2
    return 1
}

if [[ "${NO_BUILD:-0}" != "1" ]]; then
    say "building images"
    "${COMPOSE[@]}" build || exit 1
fi

say "starting the stack"
"${COMPOSE[@]}" up -d || { dump_logs; exit 1; }
wait_for_socket || { dump_logs; exit 1; }

if [[ -n "${CASES:-}" ]]; then
    read -r -a cases <<<"${CASES}"
else
    read -r -a cases <<<"$("${COMPOSE[@]}" exec -T client /harness/cases.sh --list | tr '\n' ' ')"
fi

passed=0
failed=()

# run_orphan_case drives orphan_keys_swept, the one case whose subject is a broker
# restart: a login installs a key, the broker restarts, and the key must be gone
# because the session it belonged to no longer exists anywhere (#171). A case runs
# inside the client container and cannot restart a service in another one, so the
# restart happens here, between the case's two phases.
#
# /home is deliberately not reset in between — the key the first phase installed is
# the whole subject of the second.
run_orphan_case() {
    "${COMPOSE[@]}" exec -T -e PHASE=setup client /harness/cases.sh orphan_keys_swept || return 1

    say "case orphan_keys_swept (restarting the broker between its two phases)"
    "${COMPOSE[@]}" restart broker >/dev/null 2>&1
    wait_for_socket || return 1

    "${COMPOSE[@]}" exec -T -e PHASE=check client /harness/cases.sh orphan_keys_swept
}

for name in "${cases[@]}"; do
    # Every case starts from a broker with no sessions and no in-flight device
    # flows. Otherwise a flow left polling by the previous case can be granted by
    # this case's approval, and turn up in the audit log as an event this case
    # never caused.
    if [[ "${name}" == "broker_down" ]]; then
        say "case ${name} (stopping the broker first)"
        "${COMPOSE[@]}" stop broker >/dev/null 2>&1
        # The socket file outlives the process it belonged to, and a login would
        # then fail at connect() rather than at open() — a different code path
        # from the one this case is about.
        "${COMPOSE[@]}" exec -T client rm -f "${SOCKET}"
    else
        say "case ${name}"
        "${COMPOSE[@]}" restart broker >/dev/null 2>&1
        wait_for_socket || { dump_logs; exit 1; }
        "${COMPOSE[@]}" exec -T client cp /harness/pam-sshd /etc/pam.d/sshd
    fi

    # After the restart, deliberately. The broker writes the login key from the
    # goroutine that completes the device flow, which can still be running when
    # the previous case's ssh has already exited — so a reset before the restart
    # races with it and this case starts with the previous case's key. Stopping
    # the broker first takes every in-flight flow with it, which is what makes the
    # removal final.
    reset_homes

    if [[ "${name}" == "orphan_keys_swept" ]]; then
        run_case=(run_orphan_case)
    else
        run_case=("${COMPOSE[@]}" exec -T client /harness/cases.sh "${name}")
    fi

    if "${run_case[@]}"; then
        echo "    PASS ${name}"
        passed=$((passed + 1))
    else
        echo "    FAIL ${name}"
        failed+=("${name}")
        dump_logs
    fi
done

say "${passed}/${#cases[@]} cases passed"
if [[ "${#failed[@]}" -ne 0 ]]; then
    printf 'failed: %s\n' "${failed[*]}"
    exit 1
fi
