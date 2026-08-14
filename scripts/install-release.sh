#!/bin/bash

# OIDC PAM release-tarball installer.
#
# Designed to run from the root of an extracted release archive
# (oidc-pam-<version>-linux-<arch>/), where the prebuilt binaries sit alongside
# this script and a configs/ directory. Unlike scripts/install.sh (which builds
# from source), this installs already-compiled artifacts and installs no build
# dependencies.
#
# Usage:
#   sudo ./install-release.sh            # install binaries, config, systemd unit
#   sudo ./install-release.sh --configure-pam   # additionally wire pam_oidc.so into sshd
#
# PAM is NOT modified unless --configure-pam is passed, so an install cannot
# lock you out of SSH on its own. Console login, su and sudo are never wired:
# the console is the recovery path when the broker is down.
#
# Environment:
#   PAM_MODULE_DIR=<dir>   where to install pam_oidc.so, if detection gets it
#                          wrong. It must be a directory libpam itself loads
#                          modules from, or the module will never run.

set -euo pipefail

INSTALL_DIR="/usr/local/bin"
# Where libpam loads modules from. Deliberately empty: resolve_pam_dir() detects
# it before anything is installed (#208). It used to be hardcoded to
# /lib/security, which exists on neither Debian/Ubuntu (/lib/<triplet>/security)
# nor RHEL-family systems (/lib64/security), so the install aborted part-way
# through -- after the binaries were in place -- on every distribution this
# project supports.
PAM_DIR=""
# The PAM service directory, overridable only so the logic below can be tested
# against a temporary tree instead of the host's real stack.
PAM_D_DIR="${PAM_D_DIR:-/etc/pam.d}"
CONFIG_DIR="/etc/oidc-auth"
RUN_DIR="/var/run/oidc-auth"
LOG_DIR="/var/log/oidc-auth"
# The broker's own state: the SSH keys it issues (ssh-keys/) and the per-user locks
# that serialize its authorized_keys writes (locks/). Root-only, and deliberately
# not in any user's home (#161, #171).
STATE_DIR="/var/lib/oidc-pam"
SYSTEMD_DIR="/etc/systemd/system"

CONFIGURE_PAM=0
# Set when PAM wiring was declined or refused, so the summary can say so rather
# than implying the host is configured.
PAM_WIRING_SKIPPED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Resolve the directory this script lives in so it works regardless of CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Print the header block only. The comments further down explain implementation
# rather than usage, and grepping every '^#' in the file put all of them in --help.
print_usage() {
    awk 'NR == 1 { next }
         /^#/    { seen = 1; sub(/^#[[:space:]]?/, ""); print; next }
         seen    { exit }
         { next }' "${BASH_SOURCE[0]}"
}

parse_args() {
    for arg in "$@"; do
        case "$arg" in
            --configure-pam) CONFIGURE_PAM=1 ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *) print_error "Unknown argument: $arg" ;;
        esac
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
    fi
}

# The auth line this installer adds, and the sentinel comments that fence it.
#
# The fence is what makes the uninstaller safe (#207): it used to delete every
# line matching pam_oidc.so, which on the stack this project itself ships
# (configs/pam/ssh: 'sufficient pam_oidc.so' followed by 'requisite
# pam_deny.so') left pam_deny.so as the entire auth phase and refused every
# login, for every user, permanently.
#
# 'sufficient' with nothing added after it means a broker that is down or a
# module that cannot be loaded falls through to the rest of the existing stack.
PAM_SENTINEL_BEGIN="# BEGIN oidc-pam -- added by the oidc-pam installer; removed by scripts/uninstall.sh"
PAM_SENTINEL_END="# END oidc-pam"
PAM_AUTH_LINE="auth    sufficient  pam_oidc.so"

# Locate the directory libpam loads modules from (#208).
#
# pam_permit.so ships with libpam itself, so a directory holding it is a
# directory PAM loads from. Ask the package manager first -- Debian's path
# carries a multiarch triplet not worth guessing -- then probe the known
# layouts. Prints the directory, or returns 1 having printed nothing.
detect_pam_dir() {
    local candidate dir arch

    if command -v dpkg >/dev/null 2>&1; then
        candidate="$(dpkg -L libpam-modules 2>/dev/null | grep -m1 '/pam_permit\.so$' || true)"
        if [[ -n "$candidate" && -f "$candidate" ]]; then
            dirname "$candidate"
            return 0
        fi
    fi

    if command -v rpm >/dev/null 2>&1; then
        candidate="$(rpm -ql pam 2>/dev/null | grep -m1 '/pam_permit\.so$' || true)"
        if [[ -n "$candidate" && -f "$candidate" ]]; then
            dirname "$candidate"
            return 0
        fi
    fi

    arch="$(uname -m)"
    for dir in /lib64/security /usr/lib64/security \
               "/lib/${arch}-linux-gnu/security" "/usr/lib/${arch}-linux-gnu/security" \
               /lib/security /usr/lib/security; do
        if [[ -f "$dir/pam_permit.so" ]]; then
            printf '%s\n' "$dir"
            return 0
        fi
    done

    return 1
}

# Resolve PAM_DIR, and refuse to install if it cannot be found. A module written
# outside PAM's module path never loads: with configs/pam/ssh that means every
# SSH login is refused by pam_deny.so, and on a stack with a password fallback it
# means OIDC silently never runs while the operator believes it is enforced.
resolve_pam_dir() {
    local arch
    arch="$(uname -m)"

    if [[ -n "${PAM_MODULE_DIR:-}" ]]; then
        if [[ ! -d "$PAM_MODULE_DIR" ]]; then
            print_error "PAM_MODULE_DIR=$PAM_MODULE_DIR is not a directory"
        fi
        PAM_DIR="$PAM_MODULE_DIR"
        print_warn "Using PAM_MODULE_DIR=$PAM_DIR. PAM only loads modules from its own compiled-in path; if this is not that path, pam_oidc.so will never run."
        return
    fi

    PAM_DIR="$(detect_pam_dir || true)"
    if [[ -z "$PAM_DIR" ]]; then
        print_warn "Could not find the directory PAM loads modules from."
        print_warn "Looked for pam_permit.so via dpkg/rpm and in: /lib64/security, /usr/lib64/security, /lib/${arch}-linux-gnu/security, /usr/lib/${arch}-linux-gnu/security, /lib/security, /usr/lib/security"
        print_warn "Install your distribution's PAM modules (libpam-modules on Debian/Ubuntu, pam on RHEL-family), or set PAM_MODULE_DIR to the directory holding pam_unix.so."
        print_error "Refusing to install: a module written outside PAM's module path never loads."
    fi

    print_info "PAM module directory: $PAM_DIR"
}

# Decide where pam_oidc.so belongs in an existing auth stack -- or refuse (#220).
#
# Both installers used to insert at line 1 unconditionally. Ahead of a
# pam_faillock.so preauth entry that breaks failure counting on RHEL-family
# systems; ahead of pam_nologin.so, pam_access.so or pam_securetty.so it makes
# those gates unreachable, because a 'sufficient' module that succeeds ends the
# auth phase before them.
#
# So: walk the auth phase, allow the known prologue modules to stay in front, and
# insert immediately before the first thing that authenticates or terminates
# (pam_unix.so and friends, pam_deny.so, or an include/substack of a shared
# stack). Anything unrecognised means this is not a stack we understand, and an
# installer that does not understand a stack has no business editing it.
#
# Prints "INSERT <line> <kind> <target>" (insert before that 1-based line) or
# "REFUSE <reason>".
pam_plan_insertion() {
    awk '
    function insert(n, kind, target) { print "INSERT " n " " kind " " target; done = 1; exit 0 }
    function refuse(reason)          { print "REFUSE " reason;                done = 1; exit 0 }

    BEGIN {
        # Modules that may legitimately precede OIDC: they gate or annotate a
        # login rather than deciding it, and several of them MUST run first.
        gates = "pam_env.so pam_faillock.so pam_tally.so pam_tally2.so pam_faildelay.so"
        gates = gates " pam_nologin.so pam_securetty.so pam_sepermit.so pam_access.so"
        gates = gates " pam_time.so pam_warn.so pam_keyinit.so pam_selinux.so"
        gates = gates " pam_namespace.so pam_shells.so pam_group.so pam_limits.so"
        gates = gates " pam_umask.so pam_issue.so pam_motd.so pam_mail.so pam_lastlog.so"
        gates = gates " pam_loginuid.so pam_xauth.so pam_debug.so"
        split(gates, g, " ")
        for (i in g) gate[g[i]] = 1

        # Modules that decide an authentication, or end the stack. The OIDC line
        # goes in front of the first of these.
        deciders = "pam_unix.so pam_unix2.so pam_unix_auth.so pam_pwdfile.so pam_deny.so"
        deciders = deciders " pam_permit.so pam_sss.so pam_sss_gss.so pam_ldap.so"
        deciders = deciders " pam_ldapd.so pam_krb5.so pam_winbind.so pam_localuser.so"
        deciders = deciders " pam_succeed_if.so pam_google_authenticator.so pam_oath.so"
        deciders = deciders " pam_u2f.so pam_yubico.so pam_radius_auth.so"
        deciders = deciders " pam_ssh_agent_auth.so pam_gnome_keyring.so pam_kwallet5.so"
        deciders = deciders " pam_ecryptfs.so pam_fscrypt.so pam_mount.so"
        deciders = deciders " pam_systemd_home.so pam_oidc.so"
        split(deciders, a, " ")
        for (i in a) authn[a[i]] = 1
    }

    {
        if (NF == 0 || $1 ~ /^#/) next

        # A continuation line cannot be reasoned about one line at a time.
        if ($0 ~ /\\[ \t]*$/) refuse("line " NR " continues onto the next line")

        type = tolower($1)
        sub(/^-/, "", type)

        # A whole-file include. Debian delegates sshd auth with "@include common-auth".
        if (type == "@include") {
            if ($2 ~ /auth/) insert(NR, "include", $2)
            if (seen_auth) refuse("the auth phase of this file has no module that can authenticate")
            next
        }

        if (type != "auth") {
            if (seen_auth) refuse("the auth phase of this file has no module that can authenticate")
            next
        }
        seen_auth = 1

        # Control may be a single keyword or a bracketed [value=action ...] list.
        if ($2 ~ /^\[/) {
            control = "["
            for (i = 2; i <= NF; i++) if ($i ~ /\]$/) break
            i++
        } else {
            control = tolower($2)
            i = 3
        }
        if (i > NF) refuse("cannot parse auth line " NR)

        if (control == "include" || control == "substack") insert(NR, control, $i)

        module = $i
        sub(/.*\//, "", module)
        if (module in gate) next
        if (module in authn) insert(NR, "module", module)
        refuse("unrecognised auth module " module " on line " NR)
    }

    END { if (!done) refuse("this file has no auth phase") }
    ' "$1"
}

# Explain a refusal, and print the line the operator has to add by hand (#220).
pam_print_manual_instructions() {
    local file="$1" reason="$2"

    print_warn "Not modifying $file: $reason."
    print_warn "Add this line yourself, after any pam_faillock/pam_env prologue and before the first module that authenticates:"
    print_warn "    $PAM_AUTH_LINE"
    print_warn "See configs/pam/README.md and configs/pam/ssh for the full stack, and keep a session open while testing."
}

# Insert the fenced OIDC block before line $2 of $1, preserving mode and owner.
pam_insert_block() {
    local file="$1" at="$2" tmp
    tmp="$(mktemp "${file}.oidc.XXXXXX")"

    awk -v at="$at" -v begin="$PAM_SENTINEL_BEGIN" -v body="$PAM_AUTH_LINE" -v end="$PAM_SENTINEL_END" '
        NR == at { print begin; print body; print end }
        { print }
    ' "$file" > "$tmp"

    # A PAM file is itself an access control; do not widen it by rewriting it.
    chmod --reference="$file" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
    chown --reference="$file" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$file"
}

create_directories() {
    print_info "Creating required directories..."
    install -d -m 0755 "$CONFIG_DIR"
    # 0750, and root-owned: write access to the directory holding the broker's
    # socket is enough to unlink(2) the socket and bind(2) an impostor at the same
    # path, which every PAM login then talks to (#200). The systemd unit's
    # RuntimeDirectory=/RuntimeDirectoryMode= reassert this on every start; this is
    # what the directory looks like before the first one.
    install -d -m 0750 "$RUN_DIR" "$LOG_DIR"
    # 0700: these are private keys and lock files belonging to the root broker.
    install -d -m 0700 "$STATE_DIR" "$STATE_DIR/ssh-keys" "$STATE_DIR/locks"
}

# Take the socket and log directories back to root.
#
# There is deliberately no oidc-auth account any more, and nothing is chowned to
# one. The broker runs as User=root -- it has to, since its job on a successful
# login is to write into an arbitrary account's ~/.ssh and hand the file over --
# so an unprivileged account owning a directory it writes into is a privilege
# boundary pointing the wrong way. This function used to create that account and
# chown the socket and log directories to it (#200; see scripts/install.sh for the
# full description of what that allowed).
#
# An existing host upgraded in place is repaired here rather than left as it was.
fix_directory_ownership() {
    chown -R root:root "$RUN_DIR" "$LOG_DIR"
    chmod 0750 "$RUN_DIR"

    if id "oidc-auth" &>/dev/null; then
        print_warn "The oidc-auth account exists from an earlier install and nothing runs as it; nothing is owned by it any more."
    fi
}

install_binaries() {
    print_info "Installing binaries..."

    local broker="$SCRIPT_DIR/oidc-auth-broker"
    local helper="$SCRIPT_DIR/oidc-pam-helper"
    local admin="$SCRIPT_DIR/oidc-admin"
    local pam_mod="$SCRIPT_DIR/pam_oidc.so"

    [[ -f "$broker"  ]] || print_error "oidc-auth-broker not found next to this script"
    [[ -f "$helper"  ]] || print_error "oidc-pam-helper not found next to this script"
    [[ -f "$pam_mod" ]] || print_error "pam_oidc.so not found next to this script"

    # resolve_pam_dir() runs first in main(), before anything is written.
    [[ -n "$PAM_DIR" ]] || print_error "internal error: PAM module directory not resolved"

    install -m 0755 "$broker" "$INSTALL_DIR/oidc-auth-broker"
    install -m 0755 "$helper" "$INSTALL_DIR/oidc-pam-helper"
    install -m 0644 "$pam_mod" "$PAM_DIR/pam_oidc.so"

    if [[ -f "$admin" ]]; then
        install -m 0755 "$admin" "$INSTALL_DIR/oidc-admin"
    else
        print_warn "oidc-admin not found, skipping (admin CLI will be unavailable)"
    fi

    print_info "Binaries installed"
}

install_config() {
    print_info "Installing configuration files..."

    local example_cfg="$SCRIPT_DIR/configs/examples/broker.yaml"
    local unit="$SCRIPT_DIR/configs/systemd/oidc-auth-broker.service"

    # 0600 root:root, not 0644 (#209): this file holds the AES-256 token
    # encryption key and every client secret, and the hosts this product exists
    # for are multi-user. The broker now refuses to start if it is readable by
    # anyone but root, so a mode set here is a mode the broker will hold us to.
    if [[ -f "$CONFIG_DIR/broker.yaml" ]]; then
        print_warn "$CONFIG_DIR/broker.yaml already exists, leaving its contents untouched"
        chown root:root "$CONFIG_DIR/broker.yaml"
        chmod 0600 "$CONFIG_DIR/broker.yaml"
        print_info "Tightened $CONFIG_DIR/broker.yaml to 0600 root:root"
    elif [[ -f "$example_cfg" ]]; then
        install -m 0600 -o root -g root "$example_cfg" "$CONFIG_DIR/broker.yaml"
        print_info "Installed example broker config to $CONFIG_DIR/broker.yaml (0600 root:root)"
    else
        print_warn "Example broker config not found, skipping"
    fi

    if [[ -f "$unit" ]]; then
        install -m 0644 "$unit" "$SYSTEMD_DIR/oidc-auth-broker.service"
        systemctl daemon-reload
        print_info "Installed systemd unit (not started)"
    else
        print_warn "systemd unit not found, skipping"
    fi
}

configure_pam() {
    local file="$PAM_D_DIR/sshd"
    local backup plan verdict at kind target

    if [[ "$CONFIGURE_PAM" -ne 1 ]]; then
        print_warn "PAM not modified. Re-run with --configure-pam, or add 'auth sufficient pam_oidc.so' to the relevant /etc/pam.d/ service yourself."
        PAM_WIRING_SKIPPED=1
        return
    fi

    print_info "Configuring PAM for sshd..."
    if [[ ! -f "$file" ]]; then
        print_warn "$file not found, skipping PAM wiring"
        PAM_WIRING_SKIPPED=1
        return
    fi

    # sshd and nothing else. Console login (/etc/pam.d/login) is the documented
    # recovery path when the broker is down, and su/sudo are how an operator
    # repairs the host, so none of them is wired here (#220).
    if grep -q "pam_oidc.so" "$file"; then
        print_info "pam_oidc.so already present in $file"
        print_warn "Review $file and keep an emergency session open before logging out."
        return
    fi

    plan="$(pam_plan_insertion "$file")"
    if [[ "$plan" != INSERT* ]]; then
        pam_print_manual_instructions "$file" "${plan#REFUSE }"
        PAM_WIRING_SKIPPED=1
        return
    fi
    read -r verdict at kind target <<<"$plan"
    : "$verdict"

    # Backup first, with the mode intact, and name it so the uninstaller can find
    # it (#207): scripts/uninstall.sh restores from $file.backup.* when removing
    # the OIDC lines would leave a stack that refuses every login.
    backup="$file.backup.$(date +%Y%m%d-%H%M%S)"
    cp -p "$file" "$backup"

    pam_insert_block "$file" "$at"
    print_info "Added pam_oidc.so to $file before line $at ($kind $target); backup: $backup"

    if [[ "$kind" != "module" ]] && ! grep -q "pam_faillock.so" "$file"; then
        print_warn "$file delegates its auth phase to '$target'. If that stack starts with a pam_faillock.so preauth entry, move the OIDC line below it or faillock will stop counting failures (#220)."
    fi

    print_warn "Review $file and keep an emergency session open before logging out:"
    grep -n '^[[:space:]]*\(-\?auth\|@include\)' "$file" | sed 's/^/    /'
}

print_summary() {
    cat <<EOF

========================================
OIDC PAM Installation Complete
========================================

Installed:
- Module:  $PAM_DIR/pam_oidc.so
- Config:  $CONFIG_DIR/broker.yaml (0600 root:root -- the broker refuses to start otherwise)

Next steps:
1. Note: local accounts must already exist (oidc-pam does not create users and ships no NSS module).
2. Configure your OIDC provider in $CONFIG_DIR/broker.yaml
3. Start the broker:  systemctl start oidc-auth-broker
4. Check logs:        journalctl -u oidc-auth-broker -f
$( [[ "$PAM_WIRING_SKIPPED" -eq 1 ]] && echo "5. Wire PAM:          nothing authenticates through OIDC yet -- see the [WARN] lines above" )

Console login, su and sudo are deliberately left alone: the console is the
recovery path when the broker is down. See configs/pam/README.md.

See README.md and DEPLOYMENT.md for full guidance.
EOF
}

main() {
    parse_args "$@"
    print_info "Installing OIDC PAM from release tarball..."
    check_root
    # Before anything is written: a module installed outside PAM's module path is
    # worse than no install at all (#208).
    resolve_pam_dir
    create_directories
    fix_directory_ownership
    install_binaries
    install_config
    configure_pam
    print_summary
    print_info "Done."
}

# Sourcing this file defines the functions and runs nothing, so the PAM logic
# above can be exercised against a temporary PAM_D_DIR
# (test/scripts/test-pam-wiring.sh) rather than the host's real stack.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
