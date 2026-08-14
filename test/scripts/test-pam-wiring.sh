#!/usr/bin/env bash
#
# Tests the PAM-editing logic of scripts/install.sh and scripts/uninstall.sh
# against a throwaway /etc/pam.d, without installing or uninstalling anything.
#
# Both scripts only run main() when executed, so this sources them and calls the
# functions directly with PAM_D_DIR pointed at a temporary directory. Nothing here
# touches the host's real PAM stack, needs root, or needs a Linux host.
#
# The case that matters most is "uninstall refuses to break the OIDC-only stack":
# scripts/uninstall.sh used to delete every pam_oidc.so line from /etc/pam.d/sshd,
# which on the stack configs/pam/ssh ships left 'auth requisite pam_deny.so' as
# the whole auth phase and refused every login, for every user, permanently
# (#207).
#
# Usage: test/scripts/test-pam-wiring.sh

# The assertion predicates are invoked through check(), and the print_* overrides
# are invoked by the sourced scripts, so shellcheck can see no call site for
# either. CONFIGURE_PAM and PAM_D_DIR are likewise read by the sourced scripts
# rather than by anything here.
# shellcheck disable=SC2329,SC2034

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

FAILURES=0
CASES=0

check() { # check <description> <command...>
    local desc="$1"
    shift
    CASES=$((CASES + 1))
    if "$@" >/dev/null 2>&1; then
        printf '  ok: %s\n' "$desc"
    else
        printf '  FAIL: %s\n' "$desc"
        FAILURES=$((FAILURES + 1))
    fi
}

# Predicates, so every assertion is a command and not a bare condition.
not()      { ! "$@"; }
lt()       { [[ "$1" -lt "$2" ]]; }
gt()       { [[ "$1" -gt "$2" ]]; }
eq()       { [[ "$1" -eq "$2" ]]; }
contents() { [[ "$(cat "$1")" == "$2" ]]; }
exists()   { compgen -G "$1" >/dev/null; }
line_of()  { grep -n "$1" "$2" | head -1 | cut -d: -f1; }

# Sourcing order matters only for the shared print_* helpers, which are identical
# in both scripts.
# shellcheck source=/dev/null
source "$REPO_ROOT/scripts/install.sh"
# shellcheck source=/dev/null
source "$REPO_ROOT/scripts/uninstall.sh"

# Collect the scripts' output rather than printing it; the assertions read it.
LOG="$(mktemp)"
print_info()  { echo "[INFO] $1" >> "$LOG"; }
print_warn()  { echo "[WARN] $1" >> "$LOG"; }
print_error() { echo "[ERROR] $1" >> "$LOG"; return 1; }

new_pam_dir() {
    PAM_D_DIR="$(mktemp -d)"
    : > "$LOG"
    # Both installers require --configure-pam before they will touch a PAM stack;
    # every case below except "the default does not touch PAM" is testing what
    # happens once the operator has asked for it.
    CONFIGURE_PAM=1
}

# --- fixtures ---------------------------------------------------------------

write_ubuntu_sshd() {
    cat > "$PAM_D_DIR/sshd" <<'EOF'
# PAM configuration for the Secure Shell service

# Standard Un*x authentication.
@include common-auth

# Disallow non-root logins when /etc/nologin exists.
account    required     pam_nologin.so
@include common-account
@include common-session
EOF
}

write_rhel_style_sshd() {
    cat > "$PAM_D_DIR/sshd" <<'EOF'
#%PAM-1.0
auth        required                                      pam_env.so
auth        required                                      pam_faillock.so preauth silent deny=4
auth        [default=1 ignore=ignore success=ok]           pam_succeed_if.so uid >= 1000 quiet
auth        sufficient                                    pam_unix.so nullok
auth        required                                      pam_faillock.so authfail deny=4
auth        required                                      pam_deny.so
account     required                                      pam_unix.so
EOF
}

# --- cases ------------------------------------------------------------------

echo "case: without --configure-pam neither installer touches the stack"
new_pam_dir
write_ubuntu_sshd
original="$(cat "$PAM_D_DIR/sshd")"
CONFIGURE_PAM=0
PAM_WIRING_SKIPPED=0
configure_pam > /dev/null
check "file untouched" contents "$PAM_D_DIR/sshd" "$original"
check "no backup written" not exists "$PAM_D_DIR/sshd.backup.*"
check "wiring reported as skipped" eq "$PAM_WIRING_SKIPPED" 1
check "told the operator which flag to pass" grep -q -- '--configure-pam' "$LOG"

echo "case: install inserts before the auth phase Ubuntu delegates to common-auth"
new_pam_dir
write_ubuntu_sshd
configure_pam > /dev/null
check "pam_oidc.so added" grep -q 'pam_oidc.so' "$PAM_D_DIR/sshd"
check "OIDC line precedes @include common-auth" \
    lt "$(line_of 'pam_oidc.so' "$PAM_D_DIR/sshd")" "$(line_of '@include common-auth' "$PAM_D_DIR/sshd")"
check "control is 'sufficient', so a dead broker falls through" \
    grep -q '^auth[[:space:]]*sufficient[[:space:]]*pam_oidc.so' "$PAM_D_DIR/sshd"
check "a backup was taken" exists "$PAM_D_DIR/sshd.backup.*"

echo "case: uninstall puts an installer-edited file back byte for byte"
before="$(cat "$PAM_D_DIR"/sshd.backup.*)"
PAM_CLEANUP_INCOMPLETE=0
remove_pam_config
check "no pam_oidc.so left" not grep -q 'pam_oidc.so' "$PAM_D_DIR/sshd"
check "file is identical to the pre-install content" contents "$PAM_D_DIR/sshd" "$before"
check "cleanup reported complete" eq "$PAM_CLEANUP_INCOMPLETE" 0

echo "case: install goes after the pam_faillock preauth prologue, not at line 1 (#220)"
new_pam_dir
write_rhel_style_sshd
configure_pam > /dev/null
check "OIDC line follows pam_faillock preauth" \
    gt "$(line_of 'pam_oidc.so' "$PAM_D_DIR/sshd")" "$(line_of 'pam_faillock.so preauth' "$PAM_D_DIR/sshd")"
check "OIDC line precedes pam_unix.so" \
    lt "$(line_of 'pam_oidc.so' "$PAM_D_DIR/sshd")" "$(line_of 'pam_unix.so nullok' "$PAM_D_DIR/sshd")"

echo "case: uninstall refuses to reduce the OIDC-only stack to pam_deny.so (#207)"
new_pam_dir
cp "$REPO_ROOT/configs/pam/ssh" "$PAM_D_DIR/sshd"
cp "$REPO_ROOT/configs/pam/sudo" "$PAM_D_DIR/sudo"
cp "$REPO_ROOT/configs/pam/su" "$PAM_D_DIR/su"
original="$(cat "$PAM_D_DIR/sshd")"
PAM_CLEANUP_INCOMPLETE=0
remove_pam_config
check "sshd left exactly as it was" contents "$PAM_D_DIR/sshd" "$original"
check "cleanup reported incomplete" eq "$PAM_CLEANUP_INCOMPLETE" 1
check "the operator was told what to do by hand" grep -q 'Finish by hand' "$LOG"
check "sudo was considered too, not just sshd" grep -q "$PAM_D_DIR/sudo" "$LOG"
check "su was considered too" grep -q "$PAM_D_DIR/su" "$LOG"
MODULE_LEFT_INSTALLED=0
remove_pam_module > /dev/null
check "the module is left installed while stacks reference it" eq "$MODULE_LEFT_INSTALLED" 1

echo "case: the harness stack (test/e2e/pam-sshd) is refused the same way"
new_pam_dir
cp "$REPO_ROOT/test/e2e/pam-sshd" "$PAM_D_DIR/sshd"
original="$(cat "$PAM_D_DIR/sshd")"
PAM_CLEANUP_INCOMPLETE=0
remove_pam_config
check "left exactly as it was" contents "$PAM_D_DIR/sshd" "$original"
check "cleanup reported incomplete" eq "$PAM_CLEANUP_INCOMPLETE" 1

echo "case: uninstall falls back to the installer's backup when stripping is unsafe"
new_pam_dir
write_ubuntu_sshd
cp "$PAM_D_DIR/sshd" "$PAM_D_DIR/sshd.backup.20260101-000000"
# An OIDC-only stack, as if the operator had later copied configs/pam/ssh over it.
cp "$REPO_ROOT/configs/pam/ssh" "$PAM_D_DIR/sshd"
PAM_CLEANUP_INCOMPLETE=0
remove_pam_config
check "restored from the pre-install backup" grep -q '@include common-auth' "$PAM_D_DIR/sshd"
check "no pam_oidc.so left" not grep -q 'pam_oidc.so' "$PAM_D_DIR/sshd"
check "cleanup reported complete" eq "$PAM_CLEANUP_INCOMPLETE" 0

echo "case: install refuses a stack it does not recognise, and prints the line (#220)"
new_pam_dir
printf 'auth required pam_something_local.so\nauth required pam_unix.so\n' > "$PAM_D_DIR/sshd"
original="$(cat "$PAM_D_DIR/sshd")"
PAM_WIRING_SKIPPED=0
configure_pam > /dev/null
check "file untouched" contents "$PAM_D_DIR/sshd" "$original"
check "no backup written for a file it did not edit" not exists "$PAM_D_DIR/sshd.backup.*"
check "wiring reported as skipped" eq "$PAM_WIRING_SKIPPED" 1
check "printed the exact line it would have added" grep -q 'auth    sufficient  pam_oidc.so' "$LOG"

echo "case: a file with no auth phase at all is refused"
new_pam_dir
printf 'account required pam_unix.so\nsession required pam_unix.so\n' > "$PAM_D_DIR/sshd"
PAM_WIRING_SKIPPED=0
configure_pam > /dev/null
check "wiring reported as skipped" eq "$PAM_WIRING_SKIPPED" 1
check "file untouched" not grep -q 'pam_oidc.so' "$PAM_D_DIR/sshd"

echo "case: installing twice is a no-op"
new_pam_dir
write_ubuntu_sshd
configure_pam > /dev/null
after_first="$(cat "$PAM_D_DIR/sshd")"
configure_pam > /dev/null
check "second run changed nothing" contents "$PAM_D_DIR/sshd" "$after_first"
check "only one pam_oidc.so line" eq "$(grep -c 'pam_oidc.so' "$PAM_D_DIR/sshd")" 1

echo ""
if [[ "$FAILURES" -eq 0 ]]; then
    echo "all $CASES assertions passed"
    exit 0
fi
echo "$FAILURES of $CASES assertions failed"
exit 1
