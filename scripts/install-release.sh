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
# lock you out of SSH on its own.

set -euo pipefail

INSTALL_DIR="/usr/local/bin"
PAM_DIR="/lib/security"
CONFIG_DIR="/etc/oidc-auth"
RUN_DIR="/var/run/oidc-auth"
LOG_DIR="/var/log/oidc-auth"
SYSTEMD_DIR="/etc/systemd/system"

CONFIGURE_PAM=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Resolve the directory this script lives in so it works regardless of CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

parse_args() {
    for arg in "$@"; do
        case "$arg" in
            --configure-pam) CONFIGURE_PAM=1 ;;
            -h|--help)
                grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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

create_directories() {
    print_info "Creating required directories..."
    install -d -m 0755 "$CONFIG_DIR" "$RUN_DIR" "$LOG_DIR"
}

create_user() {
    if ! id "oidc-auth" &>/dev/null; then
        useradd -r -s /bin/false -d /var/lib/oidc-auth -c "OIDC Auth Service" oidc-auth
        print_info "Created service user oidc-auth"
    else
        print_info "Service user oidc-auth already exists"
    fi
    chown -R oidc-auth:oidc-auth "$RUN_DIR" "$LOG_DIR"
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

    if [[ -f "$example_cfg" ]]; then
        if [[ -f "$CONFIG_DIR/broker.yaml" ]]; then
            print_warn "$CONFIG_DIR/broker.yaml already exists, leaving it untouched"
        else
            install -m 0644 "$example_cfg" "$CONFIG_DIR/broker.yaml"
            print_info "Installed example broker config to $CONFIG_DIR/broker.yaml"
        fi
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
    if [[ "$CONFIGURE_PAM" -ne 1 ]]; then
        print_warn "PAM not modified. Re-run with --configure-pam, or add 'auth sufficient pam_oidc.so' to the relevant /etc/pam.d/ service yourself."
        return
    fi

    print_info "Configuring PAM for sshd..."
    if [[ ! -f /etc/pam.d/sshd ]]; then
        print_warn "/etc/pam.d/sshd not found, skipping PAM wiring"
        return
    fi

    cp "/etc/pam.d/sshd" "/etc/pam.d/sshd.backup.$(date +%Y%m%d-%H%M%S)"
    if grep -q "pam_oidc.so" /etc/pam.d/sshd; then
        print_info "pam_oidc.so already present in /etc/pam.d/sshd"
    else
        sed -i '1iauth sufficient pam_oidc.so' /etc/pam.d/sshd
        print_info "Added pam_oidc.so to /etc/pam.d/sshd (backup saved)"
    fi
    print_warn "Review /etc/pam.d/sshd and keep an emergency session open before logging out."
}

print_summary() {
    cat <<EOF

========================================
OIDC PAM Installation Complete
========================================

Next steps:
1. Note: local accounts must already exist (oidc-pam does not create users and ships no NSS module).
2. Configure your OIDC provider in $CONFIG_DIR/broker.yaml
3. Start the broker:  systemctl start oidc-auth-broker
4. Check logs:        journalctl -u oidc-auth-broker -f
$( [[ "$CONFIGURE_PAM" -ne 1 ]] && echo "5. Wire PAM:          re-run with --configure-pam (or edit /etc/pam.d/<service>)" )

See README.md and DEPLOYMENT.md for full guidance.
EOF
}

main() {
    parse_args "$@"
    print_info "Installing OIDC PAM from release tarball..."
    check_root
    create_directories
    create_user
    install_binaries
    install_config
    configure_pam
    print_summary
    print_info "Done."
}

main "$@"
