#!/bin/bash

# OIDC PAM Uninstallation Script
# This script removes the OIDC PAM authentication system
#
# The one thing this script must never do is leave a host nobody can log in to.
# It used to (#207): it deleted every line matching pam_oidc.so from
# /etc/pam.d/sshd, and on the stack this project itself ships (configs/pam/ssh,
# 'auth sufficient pam_oidc.so' followed by 'auth requisite pam_deny.so') that
# left pam_deny.so as the entire auth phase -- every SSH authentication refused,
# for every user, permanently -- while printing "Uninstallation completed
# successfully!". The same edit applied to su and sudo would have taken away the
# operator's way to repair it.
#
# So, in order:
#   1. remove the OIDC lines from *every* /etc/pam.d file that references them,
#      the fenced block the installer added by preference;
#   2. check the resulting auth phase still has something that can authenticate,
#      and if it does not, restore the backup the installer took before it edited;
#   3. if there is no usable backup either, leave the file exactly as it was, say
#      so loudly, and leave pam_oidc.so installed so the stack keeps working.
#
# The check in step 2 is a static read of the stack (see
# pam_auth_phase_authenticates); it cannot prove a login succeeds. Test one
# before you close your last session.

set -euo pipefail

# Configuration
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/oidc-auth"
RUN_DIR="/var/run/oidc-auth"
LOG_DIR="/var/log/oidc-auth"
# The broker's own state: the SSH keys it issued and the per-user write locks.
STATE_DIR="/var/lib/oidc-pam"
SYSTEMD_DIR="/etc/systemd/system"
# The PAM service directory, overridable only so the logic below can be tested
# against a temporary tree instead of the host's real stack.
PAM_D_DIR="${PAM_D_DIR:-/etc/pam.d}"

# One timestamp for the whole run. It used to be recomputed per use, so the
# "backup written" message tested for a filename that differed from the one
# written whenever the second ticked over between the two lines.
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

# Set when a PAM file could not be cleaned up safely, or the module had to be
# left installed. Both make this an incomplete uninstall, and the summary says so.
PAM_CLEANUP_INCOMPLETE=0
MODULE_LEFT_INSTALLED=0
# Set when a pre-v0.5.1 oidc-auth account was found and kept, so the summary only
# mentions it on the hosts that actually have one.
USER_LEFT_BEHIND=0

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

# Every directory pam_oidc.so could have been installed into: what this host's
# libpam actually loads from, plus the layouts of the distributions this project
# supports, plus /lib/security -- which is where releases up to v0.4.2 put it
# (#208), and which is therefore exactly where a stale copy will be.
pam_module_candidate_dirs() {
    local arch dir
    arch="$(uname -m)"

    if [[ -n "${PAM_MODULE_DIR:-}" ]]; then
        printf '%s\n' "$PAM_MODULE_DIR"
    fi

    if command -v dpkg >/dev/null 2>&1; then
        dir="$(dpkg -L libpam-modules 2>/dev/null | grep -m1 '/pam_permit\.so$' || true)"
        [[ -n "$dir" ]] && dirname "$dir"
    fi

    if command -v rpm >/dev/null 2>&1; then
        dir="$(rpm -ql pam 2>/dev/null | grep -m1 '/pam_permit\.so$' || true)"
        [[ -n "$dir" ]] && dirname "$dir"
    fi

    printf '%s\n' /lib64/security /usr/lib64/security \
        "/lib/${arch}-linux-gnu/security" "/usr/lib/${arch}-linux-gnu/security" \
        /lib/security /usr/lib/security
    return 0
}

# The PAM service files that reference pam_oidc.so.
#
# Every one of them, not just sshd: the old script edited sshd alone, so a host
# that had followed configs/pam/README.md was left with /etc/pam.d/sudo, su and
# login pointing at a module that had just been deleted, each backed by
# 'requisite pam_deny.so' -- sudo and su then denying everyone, so the operator
# could not escalate to repair sshd.
#
# Backups and package-manager leftovers are skipped: they are not live stacks,
# and a backup that still mentions pam_oidc.so must not make this script think
# the module is still in use.
pam_service_files() {
    local f name
    for f in "$PAM_D_DIR"/*; do
        [[ -f "$f" ]] || continue
        name="$(basename "$f")"
        case "$name" in
            *.backup.*|*.bak|*.orig|*.save|*.rpmsave|*.rpmnew|*.dpkg-*|*.ucf-*|*~) continue ;;
            *.oidc-uninstall.*|*.oidc.*) continue ;;
        esac
        grep -q "pam_oidc.so" "$f" && printf '%s\n' "$f"
    done
    return 0
}

# Write $1 to stdout with the OIDC lines taken out: the fenced block the
# installer added, any line naming pam_oidc.so in any phase, and the bare
# "# OIDC PAM Authentication" comment older installers wrote.
pam_strip_oidc() {
    awk '
    /^[ \t]*#[ \t]*BEGIN oidc-pam/ { inblock = 1; next }
    /^[ \t]*#[ \t]*END oidc-pam/   { inblock = 0; next }
    inblock { next }
    /^[ \t]*#[ \t]*OIDC PAM Authentication[ \t]*$/ { next }
    {
        if ($0 ~ /^[ \t]*#/) { print; next }
        for (i = 1; i <= NF; i++) {
            m = $i
            sub(/.*\//, "", m)
            if (m == "pam_oidc.so") next
        }
        print
    }
    ' "$1"
}

# Does the auth phase of $1 still have something that can authenticate?
#
# This is the check that was missing in #207. "Something that can authenticate"
# means: a module that is not one of the known prologue/bookkeeping modules and
# is not pam_deny.so, reached before any required/requisite pam_deny.so, or an
# include/substack of a shared stack (which we do not follow -- a distribution's
# common-auth is assumed to authenticate).
#
# It is deliberately generous about modules it does not know: the failure being
# guarded against is a stack with nothing left in it but pam_deny.so.
pam_auth_phase_authenticates() {
    awk '
    BEGIN {
        gates = "pam_env.so pam_faillock.so pam_tally.so pam_tally2.so pam_faildelay.so"
        gates = gates " pam_nologin.so pam_securetty.so pam_sepermit.so pam_access.so"
        gates = gates " pam_time.so pam_warn.so pam_keyinit.so pam_selinux.so"
        gates = gates " pam_namespace.so pam_shells.so pam_group.so pam_limits.so"
        gates = gates " pam_umask.so pam_issue.so pam_motd.so pam_mail.so pam_lastlog.so"
        gates = gates " pam_loginuid.so pam_xauth.so pam_debug.so"
        split(gates, g, " ")
        for (i in g) gate[g[i]] = 1
    }

    {
        if (NF == 0 || $1 ~ /^#/) next

        type = tolower($1)
        sub(/^-/, "", type)

        if (type == "@include") {
            if ($2 ~ /auth/) { ok = 1; exit }
            next
        }
        if (type != "auth") next

        if ($2 ~ /^\[/) {
            control = "["
            for (i = 2; i <= NF; i++) if ($i ~ /\]$/) break
            i++
        } else {
            control = tolower($2)
            i = 3
        }
        if (i > NF) next

        if (control == "include" || control == "substack") { ok = 1; exit }

        module = $i
        sub(/.*\//, "", module)

        # A hard deny reached before anything that authenticates refuses every
        # login, whatever follows it.
        if (module == "pam_deny.so") {
            if (control == "required" || control == "requisite" || control == "[") exit
            next
        }
        # pam_oidc.so does not count: it is what is being removed, and after
        # removal the module file will not even be there.
        if (module == "pam_oidc.so") next
        if (module in gate) next

        ok = 1
        exit
    }

    END { exit(ok ? 0 : 1) }
    ' "$1"
}

# The newest $1.backup.* that predates OIDC (does not mention pam_oidc.so) and
# has a working auth phase. This is the backup the installer takes before it
# edits; the old uninstaller wrote one and then never used it.
pam_pre_install_backup() {
    local file="$1" b
    local -a candidates=()

    for b in "$file".backup.*; do
        [[ -f "$b" ]] || continue
        [[ "$b" == *.backup.uninstall.* ]] && continue
        candidates+=("$b")
    done
    [[ ${#candidates[@]} -eq 0 ]] && return 1

    # The names carry a %Y%m%d-%H%M%S stamp, which sorts lexicographically.
    while IFS= read -r b; do
        grep -q "pam_oidc.so" "$b" && continue
        pam_auth_phase_authenticates "$b" || continue
        printf '%s\n' "$b"
        return 0
    done < <(printf '%s\n' "${candidates[@]}" | sort -r)

    return 1
}

# Take OIDC out of one PAM service file, or leave it alone and say why.
remove_pam_config_from_file() {
    local file="$1" service
    local backup="$file.backup.uninstall.$TIMESTAMP"
    local candidate restored
    service="$(basename "$file")"

    cp -p "$file" "$backup"

    candidate="$(mktemp "${file}.oidc-uninstall.XXXXXX")"
    pam_strip_oidc "$file" > "$candidate"

    if pam_auth_phase_authenticates "$candidate"; then
        # Preserve mode and owner: a PAM file is itself an access control.
        chmod --reference="$file" "$candidate" 2>/dev/null || chmod 0644 "$candidate"
        chown --reference="$file" "$candidate" 2>/dev/null || true
        mv -f "$candidate" "$file"
        print_info "Removed pam_oidc.so from $file (backup: $backup)"
        return 0
    fi
    rm -f "$candidate"

    print_warn "$file: deleting its pam_oidc.so lines would leave an auth phase that refuses every login."

    restored="$(pam_pre_install_backup "$file" || true)"
    if [[ -n "$restored" ]]; then
        cp -p "$restored" "$file"
        print_info "Restored $file from $restored, the copy taken before pam_oidc.so was added."
        print_warn "Test a login through $service before you close your last session: the check here reads the stack, it does not authenticate."
        return 0
    fi

    print_warn "There is no pre-install backup of $file to restore, so it has been left exactly as it was."
    print_warn "Its auth phase has no authentication other than OIDC -- most likely it is a copy of configs/pam/$service, whose 'auth requisite pam_deny.so' refuses anything OIDC did not accept."
    print_warn "Finish by hand, with a session already open, and re-run this script:"
    print_warn "  Debian/Ubuntu:  replace the auth phase of $file with '@include common-auth'"
    print_warn "  RHEL-family:    replace it with 'auth  substack  system-auth'"
    print_warn "  or copy your own pre-OIDC version of the file back."
    print_warn "pam_oidc.so is being left installed, so $service keeps working until you do."
    return 1
}

# Remove PAM configuration
remove_pam_config() {
    print_info "Removing OIDC from PAM configuration in $PAM_D_DIR..."

    local -a files=()
    local f
    while IFS= read -r f; do
        [[ -n "$f" ]] && files+=("$f")
    done < <(pam_service_files)

    if [[ ${#files[@]} -eq 0 ]]; then
        print_info "No PAM service file references pam_oidc.so"
        return
    fi

    for f in "${files[@]}"; do
        remove_pam_config_from_file "$f" || PAM_CLEANUP_INCOMPLETE=1
    done
}

# Stop and disable services
stop_services() {
    print_info "Stopping services..."

    if ! command -v systemctl >/dev/null 2>&1; then
        print_warn "systemctl not found, skipping service removal"
        return
    fi

    # Stop service if running
    if systemctl is-active --quiet oidc-auth-broker.service; then
        systemctl stop oidc-auth-broker.service
        print_info "Service stopped"
    fi

    # Disable service
    if systemctl is-enabled --quiet oidc-auth-broker.service 2>/dev/null; then
        systemctl disable oidc-auth-broker.service
        print_info "Service disabled"
    fi

    # Remove systemd service file
    if [[ -f "$SYSTEMD_DIR/oidc-auth-broker.service" ]]; then
        rm -f "$SYSTEMD_DIR/oidc-auth-broker.service"
        print_info "Systemd service file removed"
    fi

    systemctl daemon-reload
}

# Remove binaries
remove_binaries() {
    print_info "Removing binaries..."

    if [[ -f "$INSTALL_DIR/oidc-auth-broker" ]]; then
        rm -f "$INSTALL_DIR/oidc-auth-broker"
        print_info "Broker binary removed"
    fi

    if [[ -f "$INSTALL_DIR/oidc-pam-helper" ]]; then
        rm -f "$INSTALL_DIR/oidc-pam-helper"
        print_info "Helper binary removed"
    fi

    if [[ -f "$INSTALL_DIR/oidc-admin" ]]; then
        rm -f "$INSTALL_DIR/oidc-admin"
        print_info "Admin binary removed"
    fi

    remove_pam_module
}

# Remove the PAM module itself -- but never while a live stack still names it.
#
# An unresolvable module is not a no-op: in configs/pam/ssh the 'sufficient' line
# fails and the login falls through to 'auth requisite pam_deny.so', so removing
# the .so out from under a stack that still references it is the same lockout by
# another route.
remove_pam_module() {
    local -a remaining=()
    local f dir removed=0

    while IFS= read -r f; do
        [[ -n "$f" ]] && remaining+=("$f")
    done < <(pam_service_files)

    if [[ ${#remaining[@]} -gt 0 ]]; then
        print_warn "Not removing pam_oidc.so: these PAM service files still reference it:"
        printf '    %s\n' "${remaining[@]}"
        print_warn "A stack that names a module which is not there fails that module, and with 'auth requisite pam_deny.so' below it that means every login is refused."
        MODULE_LEFT_INSTALLED=1
        return
    fi

    while IFS= read -r dir; do
        if [[ -f "$dir/pam_oidc.so" ]]; then
            rm -f "$dir/pam_oidc.so"
            print_info "PAM module removed: $dir/pam_oidc.so"
            removed=1
        fi
    done < <(pam_module_candidate_dirs)

    if [[ "$removed" -eq 0 ]]; then
        print_info "No pam_oidc.so found to remove"
    fi
}

# Remove configuration and data
remove_config() {
    print_info "Removing configuration and data..."

    # Ask user about configuration removal
    read -p "Remove configuration directory $CONFIG_DIR? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ -d "$CONFIG_DIR" ]]; then
            rm -rf -- "$CONFIG_DIR"
            print_info "Configuration directory removed"
        fi
    else
        print_warn "Configuration directory preserved -- $CONFIG_DIR/broker.yaml holds the token encryption key and your client secrets"
    fi

    # Ask user about log removal
    read -p "Remove log directory $LOG_DIR? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ -d "$LOG_DIR" ]]; then
            rm -rf -- "$LOG_DIR"
            print_info "Log directory removed"
        fi
    else
        print_info "Log directory preserved"
    fi

    # Remove runtime directory
    if [[ -d "$RUN_DIR" ]]; then
        rm -rf -- "$RUN_DIR"
        print_info "Runtime directory removed"
    fi
}

# Remove the broker's own state: the SSH private keys it issued to users, and the
# per-user write locks. The old script never touched this, so every key the broker
# had ever issued stayed on disk after an uninstall.
remove_state() {
    if [[ ! -d "$STATE_DIR" ]]; then
        return
    fi

    print_warn "$STATE_DIR holds the SSH private keys the broker issued to users."
    read -p "Remove $STATE_DIR? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf -- "$STATE_DIR"
        print_info "Broker state directory removed"
    else
        print_warn "State directory preserved -- the private keys it issued stay on disk"
    fi
}

# The numeric owner of $1, without following a symlink. Prints nothing on failure.
path_owner_uid() {
    stat -c %u "$1" 2>/dev/null || stat -f %u "$1" 2>/dev/null || true
}

# Remove the authorized_keys entries the broker wrote.
#
# Broker-issued entries are recognisable exactly as the broker recognises them
# (pkg/ssh/entry.go): a "<user>@oidc-pam-<unix>" comment on the key line, under a
# "# Added by OIDC PAM on <time>" provenance line. A key the user put there
# themselves has neither and is left alone. They also carry expiry-time=, so sshd
# stops honouring them by itself -- this is about not leaving them behind.
#
# This runs as root over paths the account being swept controls, which is the
# defect class #204/#225 covers on the broker side: `ln -s /etc/shadow
# ~/.ssh/authorized_keys` would otherwise have root copy that file into the user's
# home and then overwrite it with the filtered output. So neither ~/.ssh nor the
# file itself may be a symlink, and both must belong to the account whose keys
# these are -- the same conditions sshd's own StrictModes applies before reading
# the file. A shell cannot do this without a check-then-use window (there is no
# openat(2) here); the window is between the stat and the rewrite of a path only
# root and that one account can write to, and the alternative is leaving issued
# keys on disk. `oidc-admin` is the tool to use for a hostile multi-user host.
sweep_authorized_keys() {
    local uid home sshdir path backup owner swept=0

    read -p "Remove broker-issued entries from users' authorized_keys files? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warn "authorized_keys files left alone -- broker-issued entries remain until their expiry-time= passes"
        return
    fi

    # Fields counted from the right for the home directory: uid and gid sit ahead
    # of GECOS, but GECOS is the one field that can itself contain a colon, so
    # $6 is not reliably the home directory while $(NF-1) is.
    while IFS=$'\t' read -r uid home; do
        [[ -n "$home" && -d "$home" ]] || continue
        sshdir="$home/.ssh"
        path="$sshdir/authorized_keys"

        if [[ -L "$sshdir" || -L "$path" ]]; then
            print_warn "Skipping $path: it or its .ssh directory is a symlink, and following it as root would rewrite whatever it points at"
            continue
        fi
        [[ -f "$path" ]] || continue

        for owner in "$(path_owner_uid "$sshdir")" "$(path_owner_uid "$path")"; do
            if [[ "$owner" != "$uid" && "$owner" != "0" ]]; then
                print_warn "Skipping $path: it is owned by uid ${owner:-unknown}, not by uid $uid or root"
                continue 2
            fi
        done

        grep -q "@oidc-pam-" "$path" || continue

        backup="$path.backup.oidc-uninstall.$TIMESTAMP"
        cp -p "$path" "$backup"
        if awk '
            /^[ \t]*#[ \t]*Added by OIDC PAM on/ { next }
            { for (i = 1; i <= NF; i++) if (index($i, "@oidc-pam-")) next; print }
        ' "$backup" > "$path"; then
            print_info "Swept broker-issued keys from $path (backup: $backup)"
            swept=1
        else
            cp -p "$backup" "$path"
            print_warn "Could not rewrite $path; restored it from $backup"
        fi
    done < <(getent passwd | awk -F: 'NF >= 7 { printf "%s\t%s\n", $3, $(NF-1) }')

    if [[ "$swept" -eq 0 ]]; then
        print_info "No broker-issued authorized_keys entries found"
    fi
}

# Remove the leftover oidc-auth service account.
#
# Nothing has run as it since #200: the broker runs as root -- it has to, because
# on a successful login it writes into an arbitrary account's ~/.ssh and hands the
# file over -- and installers up to v0.4.2 nonetheless created this account and
# gave it the socket and log directories, which is a privilege boundary pointing
# the wrong way. Only a host installed by one of those versions has the account,
# so it is offered for removal rather than assumed to exist.
remove_user() {
    if ! id "oidc-auth" &>/dev/null; then
        return
    fi

    print_warn "The oidc-auth account exists from an install before v0.5.1. Nothing runs as it and nothing is owned by it any more."
    read -p "Remove the oidc-auth user? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if userdel oidc-auth; then
            print_info "User oidc-auth removed"
        else
            print_warn "userdel failed; check whether any file is still owned by oidc-auth (find / -user oidc-auth)"
        fi
    else
        USER_LEFT_BEHIND=1
        print_info "User oidc-auth preserved"
    fi
}

# Print uninstallation summary
print_summary() {
    echo ""
    echo "========================================"
    echo "OIDC PAM Uninstallation Complete"
    echo "========================================"
    echo ""
    echo "Removed components:"
    echo "- Binaries from $INSTALL_DIR"
    if [[ "$MODULE_LEFT_INSTALLED" -eq 0 ]]; then
        echo "- PAM module (pam_oidc.so)"
    fi
    echo "- Systemd service"
    echo "- OIDC lines from the PAM service files that had them (each backed up)"
    echo ""
    echo "Preserved (if chosen):"
    echo "- Configuration: $CONFIG_DIR"
    echo "- Logs: $LOG_DIR"
    echo "- Broker state: $STATE_DIR"
    [[ "$USER_LEFT_BEHIND" -eq 1 ]] && echo "- User: oidc-auth (from an install before v0.5.1; nothing runs as it)"
    echo ""

    if [[ "$PAM_CLEANUP_INCOMPLETE" -eq 1 || "$MODULE_LEFT_INSTALLED" -eq 1 ]]; then
        print_warn "THIS UNINSTALL IS NOT FINISHED."
        [[ "$PAM_CLEANUP_INCOMPLETE" -eq 1 ]] && print_warn "At least one PAM file was left as it was, because taking OIDC out of it would have refused every login. See the [WARN] lines above."
        [[ "$MODULE_LEFT_INSTALLED" -eq 1 ]] && print_warn "pam_oidc.so is still installed, deliberately: a PAM stack still references it."
        echo ""
    fi

    echo "Before you close your last session, test a login for every service you"
    echo "changed. Manual cleanup may still be needed for:"
    echo "- PAM stacks this script would not edit (listed above, if any)"
    echo "- SSH configuration changes (UsePAM, KbdInteractiveAuthentication)"
    echo "- Firewall rules"
    echo ""
    echo "To reinstall, run: ./scripts/install.sh"
}

# Main uninstallation function
main() {
    print_info "Starting OIDC PAM uninstallation..."

    check_root

    # Confirmation
    echo "This will remove OIDC PAM authentication system from your system."
    read -p "Are you sure you want to continue? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Uninstallation cancelled"
        exit 0
    fi

    stop_services
    # PAM first, and the module only once no stack references it: order is the
    # whole safety property here.
    remove_pam_config
    remove_binaries
    remove_config
    remove_state
    sweep_authorized_keys
    remove_user
    print_summary

    if [[ "$PAM_CLEANUP_INCOMPLETE" -eq 1 || "$MODULE_LEFT_INSTALLED" -eq 1 ]]; then
        print_warn "Uninstallation finished with manual steps outstanding (see above)."
        exit 1
    fi
    print_info "Uninstallation completed successfully!"
}

# Sourcing this file defines the functions and runs nothing, so the PAM logic
# above can be exercised against a temporary PAM_D_DIR
# (test/scripts/test-pam-wiring.sh) rather than the host's real stack.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
