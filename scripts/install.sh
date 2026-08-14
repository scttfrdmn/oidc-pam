#!/bin/bash

# OIDC PAM installer, building from source in this working tree.
#
# For a prebuilt release tarball, use scripts/install-release.sh instead.
#
# Usage:
#   sudo ./scripts/install.sh                  # build and install; PAM untouched
#   sudo ./scripts/install.sh --configure-pam  # additionally wire pam_oidc.so into sshd
#
# PAM is NOT modified unless --configure-pam is passed, so an install cannot lock
# you out of SSH on its own. Console login, su and sudo are never wired: the
# console is the recovery path when the broker is down.
#
# Environment:
#   PAM_MODULE_DIR=<dir>   where to install pam_oidc.so, if detection gets it
#                          wrong. It must be a directory libpam itself loads
#                          modules from, or the module will never run.

set -e

# Configuration
INSTALL_DIR="/usr/local/bin"
# Where libpam loads modules from. Deliberately empty: resolve_pam_dir() detects
# it before anything is installed (#208). It used to be hardcoded to
# /lib/security, which exists on neither Debian/Ubuntu (/lib/<triplet>/security)
# nor RHEL-family systems (/lib64/security), so the install either aborted
# half-way through or -- once an operator created the directory to get past that
# -- wrote the module somewhere PAM never looks. Override with PAM_MODULE_DIR.
PAM_DIR=""
# The PAM service directory, overridable only so the logic below can be tested
# against a temporary tree instead of the host's real stack.
PAM_D_DIR="${PAM_D_DIR:-/etc/pam.d}"
CONFIG_DIR="/etc/oidc-auth"
RUN_DIR="/var/run/oidc-auth"
LOG_DIR="/var/log/oidc-auth"
# The broker's own state: SSH keys it issues, and the per-user locks that
# serialize its authorized_keys writes. 0700 and root-owned, because a lock a
# user can take is a lock a user can hold (#161).
STATE_DIR="/var/lib/oidc-pam"
SYSTEMD_DIR="/etc/systemd/system"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print functions
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if running as root
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
# An install must not be able to lock the operator out.
PAM_SENTINEL_BEGIN="# BEGIN oidc-pam -- added by the oidc-pam installer; removed by scripts/uninstall.sh"
PAM_SENTINEL_END="# END oidc-pam"
PAM_AUTH_LINE="auth    sufficient  pam_oidc.so"

# Whether to wire pam_oidc.so into /etc/pam.d/sshd at all. Off by default, so an
# install cannot cost you the session you ran it from; --configure-pam turns it on.
CONFIGURE_PAM=0

# Set when PAM wiring was declined, so the summary can say so rather than
# implying the host is configured.
PAM_WIRING_SKIPPED=0

# Print the header block only, as scripts/install-release.sh does: the comments
# further down explain implementation rather than usage.
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

# Check system requirements
check_requirements() {
    print_info "Checking system requirements..."
    
    # Check for required commands
    local required_commands=("systemctl" "id" "getent")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            print_error "Required command '$cmd' not found"
        fi
    done
    
    # Check for PAM
    if [[ ! -d "/etc/pam.d" ]]; then
        print_error "PAM configuration directory not found"
    fi
    
    # Check for systemd
    if [[ ! -d "/etc/systemd/system" ]]; then
        print_error "systemd not found"
    fi
    
    print_info "System requirements check passed"
}

# Install system dependencies
install_dependencies() {
    print_info "Installing system dependencies..."
    
    # Detect OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
    else
        print_error "Cannot detect operating system"
    fi
    
    case "$OS" in
        ubuntu|debian)
            apt-get update
            apt-get install -y libpam0g-dev libjson-c-dev pkg-config libsystemd-dev
            ;;
        rhel|centos|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y pam-devel json-c-devel pkgconfig systemd-devel
            else
                yum install -y pam-devel json-c-devel pkgconfig systemd-devel
            fi
            ;;
        *)
            print_warn "Unsupported OS: $OS. Please install dependencies manually."
            ;;
    esac
    
    print_info "Dependencies installed"
}

# Create required directories
create_directories() {
    print_info "Creating required directories..."
    
    # Create directories with proper permissions
    mkdir -p "$CONFIG_DIR"
    chmod 755 "$CONFIG_DIR"
    
    mkdir -p "$RUN_DIR"
    chmod 755 "$RUN_DIR"
    
    # 0750, not 0755: the broker's own log is the delivery mechanism for anything
    # it debug-logs about a login in progress, so it is not world-readable.
    mkdir -p "$LOG_DIR"
    chmod 750 "$LOG_DIR"

    mkdir -p "$STATE_DIR/ssh-keys" "$STATE_DIR/locks"
    chmod 700 "$STATE_DIR" "$STATE_DIR/ssh-keys" "$STATE_DIR/locks"

    print_info "Directories created"
}

# Take the socket, log and state directories back to root.
#
# There is deliberately no oidc-auth account any more, and nothing is chowned to
# one. The broker runs as User=root -- it has to, because its job on a successful
# login is to write into an arbitrary account's ~/.ssh and hand the file over --
# so an unprivileged account owning any directory it writes to is a privilege
# boundary pointing the wrong way.
#
# This function used to create the account and then `chown -R oidc-auth:oidc-auth`
# the socket and log directories. Write access to the directory holding the socket
# is enough to unlink(2) that socket and bind(2) an impostor at the same path: the
# real broker keeps serving on its now-unlinked inode and stays green in
# `systemctl status`, while every PAM login reaches the impostor, which can answer
# {"success":true} and -- with `auth sufficient pam_oidc.so` -- log anyone in as
# anyone, root included (#200). The log directory was the same shape: a root
# process appending to a file an unprivileged account can replace with a symlink.
#
# The broker now refuses to bind under a directory anyone but root or itself can
# write to, so an installed host that still has the old ownership fails to start
# rather than serving from a hijackable path, and the systemd unit's
# RuntimeDirectory=/RuntimeDirectoryMode= reassert root:root 0750 on every start.
# This is the part that stops the wrong ownership being created in the first place.
#
# An existing host upgraded in place is repaired here rather than left as it was.
fix_directory_ownership() {
    print_info "Setting directory ownership to root..."

    chown -R root:root "$RUN_DIR" "$LOG_DIR"
    chmod 0750 "$RUN_DIR"

    if id "oidc-auth" &>/dev/null; then
        print_warn "The oidc-auth account exists from an earlier install and nothing runs as it."
        print_warn "Nothing is owned by it any more; remove it with 'userdel oidc-auth' once you have checked no other software uses it."
    fi
}

# Install binaries
install_binaries() {
    print_info "Installing binaries..."
    
    # Check if binaries exist
    if [[ ! -f "bin/oidc-auth-broker" ]]; then
        print_error "Binary bin/oidc-auth-broker not found. Please run 'make build' first."
    fi
    
    if [[ ! -f "bin/oidc-pam-helper" ]]; then
        print_error "Binary bin/oidc-pam-helper not found. Please run 'make build' first."
    fi
    
    if [[ ! -f "bin/pam_oidc.so" ]]; then
        print_error "PAM module bin/pam_oidc.so not found. Please run 'make build' first."
    fi
    
    # resolve_pam_dir() runs first in main(), before anything is written.
    if [[ -z "$PAM_DIR" ]]; then
        print_error "internal error: PAM module directory not resolved"
    fi

    # Install binaries
    install -m 0755 bin/oidc-auth-broker "$INSTALL_DIR/oidc-auth-broker"
    install -m 0755 bin/oidc-pam-helper "$INSTALL_DIR/oidc-pam-helper"
    install -m 0644 bin/pam_oidc.so "$PAM_DIR/pam_oidc.so"

    print_info "Binaries installed ($PAM_DIR/pam_oidc.so)"
}

# Install configuration files
install_config() {
    print_info "Installing configuration files..."
    
    # Install broker configuration.
    #
    # 0600 root:root, not 0644 (#209): this file holds the AES-256 token
    # encryption key and every client secret, and the hosts this product exists
    # for are multi-user. The broker now refuses to start if it is readable by
    # anyone but root, so a mode set here is a mode the broker will hold us to.
    if [[ -f "$CONFIG_DIR/broker.yaml" ]]; then
        print_warn "$CONFIG_DIR/broker.yaml already exists, leaving its contents untouched"
        chown root:root "$CONFIG_DIR/broker.yaml"
        chmod 0600 "$CONFIG_DIR/broker.yaml"
        print_info "Tightened $CONFIG_DIR/broker.yaml to 0600 root:root"
    elif [[ -f "configs/examples/broker.yaml" ]]; then
        install -m 0600 -o root -g root configs/examples/broker.yaml "$CONFIG_DIR/broker.yaml"
        print_info "Broker configuration installed (0600 root:root)"
    else
        print_warn "Broker configuration not found, skipping"
    fi
    
    # Install systemd service
    if [[ -f "configs/systemd/oidc-auth-broker.service" ]]; then
        cp configs/systemd/oidc-auth-broker.service "$SYSTEMD_DIR/"
        chmod 644 "$SYSTEMD_DIR/oidc-auth-broker.service"
        print_info "Systemd service installed"
    else
        print_warn "Systemd service file not found, skipping"
    fi
}

# Configure PAM
#
# Only /etc/pam.d/sshd is touched, and only that file. The host-wide stacks
# (common-auth on Debian/Ubuntu, system-auth on RHEL) are @included by every
# service on the machine — su, sudo, the display manager, polkit, cron — and a
# device flow in one of those makes each of them wait up to 90 s for a human with
# a phone, several with no way to show that human the verification URL (#172).
configure_pam() {
    local file="$PAM_D_DIR/sshd"
    local backup plan verdict at kind target

    # Opt-in, as in scripts/install-release.sh, and for the same reason: an
    # install that edits the host's SSH auth stack without being asked is an
    # install that can cost you the session you ran it from. The two installers
    # used to disagree about this -- the release one asked, this one did not --
    # and a divergence like that gets one of them fixed and the other forgotten.
    if [[ "$CONFIGURE_PAM" -ne 1 ]]; then
        print_warn "PAM not modified. Re-run with --configure-pam, or add 'auth sufficient pam_oidc.so' to $PAM_D_DIR/sshd yourself."
        PAM_WIRING_SKIPPED=1
        return
    fi

    print_info "Configuring PAM..."

    if [[ ! -f "$file" ]]; then
        print_warn "$file not found, skipping PAM configuration"
        PAM_WIRING_SKIPPED=1
        return
    fi

    # Console login (/etc/pam.d/login) is deliberately NOT wired (#220): it is the
    # documented recovery path when the broker is down, and it has to keep working
    # without the broker. Same for su and sudo -- an operator who cannot escalate
    # cannot repair anything. See configs/pam/README.md.
    if grep -q "pam_oidc.so" "$file"; then
        print_info "OIDC PAM already configured in $file"
        print_warn "Review $file and keep an emergency session open."
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

    print_warn "PAM configuration updated. Please review $file:"
    grep -n '^[[:space:]]*\(-\?auth\|@include\)' "$file" | sed 's/^/    /'
    print_warn "Keep an emergency session open. Wire pam_oidc.so per service only, never into the"
    print_warn "host-wide stack every service includes -- see configs/pam/README.md."
}

# Enable and start services
enable_services() {
    print_info "Enabling services..."
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable but don't start the service (requires configuration)
    systemctl enable oidc-auth-broker.service
    
    print_info "Services enabled"
    print_warn "Service not started. Please configure /etc/oidc-auth/broker.yaml first"
}

# Post-installation tasks
post_install() {
    print_info "Running post-installation tasks..."
    
    # Create log file. 0640, not 0644: see the note on $LOG_DIR above. root-owned,
    # because the broker that appends to it runs as root -- a log file an
    # unprivileged account owns is one it can replace with a symlink.
    touch "$LOG_DIR/broker.log"
    chown root:root "$LOG_DIR/broker.log"
    chmod 640 "$LOG_DIR/broker.log"

    # Create the socket directory: root-owned and 0750, not 0755. Write access here
    # is enough to unlink the broker's socket and bind an impostor at the same path
    # (#200). systemd's RuntimeDirectory= recreates it with these same values on
    # every start; this is what it looks like before the first one.
    mkdir -p "$RUN_DIR"
    chown root:root "$RUN_DIR"
    chmod 750 "$RUN_DIR"
    
    print_info "Post-installation tasks completed"
}

# Print installation summary
print_summary() {
    echo ""
    echo "========================================"
    echo "OIDC PAM Installation Complete"
    echo "========================================"
    echo ""
    echo "Next steps:"
    echo "1. Configure OIDC provider in $CONFIG_DIR/broker.yaml"
    echo "2. Start the service: systemctl start oidc-auth-broker"
    echo "3. Check logs: journalctl -u oidc-auth-broker -f"
    echo "4. Test authentication: oidc-pam-helper --user testuser"
    echo ""
    echo "Configuration files:"
    echo "- Broker: $CONFIG_DIR/broker.yaml (0600 root:root -- the broker refuses to start otherwise)"
    echo "- PAM: $PAM_D_DIR/sshd"
    echo "- Module: $PAM_DIR/pam_oidc.so"
    echo "- Service: $SYSTEMD_DIR/oidc-auth-broker.service"
    echo ""
    echo "Log files:"
    echo "- Broker: $LOG_DIR/broker.log"
    echo "- System: journalctl -u oidc-auth-broker"
    echo ""
    if [[ "$PAM_WIRING_SKIPPED" -eq 1 ]]; then
        echo "PAM was NOT wired: nothing on this host authenticates through OIDC yet."
        echo "See the [WARN] lines above for the line to add and where to add it."
        echo ""
    fi
    echo "Console login, su and sudo are deliberately left alone: the console is the"
    echo "recovery path when the broker is down. See configs/pam/README.md."
    echo ""
    echo "For more information, see README.md and REQUIREMENTS.md"
}

# Main installation function
main() {
    parse_args "$@"
    print_info "Starting OIDC PAM installation..."

    check_root
    check_requirements
    # Before anything is written: a module installed outside PAM's module path is
    # worse than no install at all (#208).
    resolve_pam_dir
    install_dependencies
    create_directories
    fix_directory_ownership
    install_binaries
    install_config
    configure_pam
    enable_services
    post_install
    print_summary

    print_info "Installation completed successfully!"
}

# Sourcing this file defines the functions and runs nothing, so the PAM logic
# above can be exercised against a temporary PAM_D_DIR
# (test/scripts/test-pam-wiring.sh) rather than the host's real stack.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi