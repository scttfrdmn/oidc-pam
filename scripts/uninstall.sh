#!/bin/bash

# OIDC PAM Uninstallation Script
# This script removes the OIDC PAM authentication system

set -e

# Configuration
INSTALL_DIR="/usr/local/bin"
PAM_DIR="/lib/security"
CONFIG_DIR="/etc/oidc-auth"
RUN_DIR="/var/run/oidc-auth"
LOG_DIR="/var/log/oidc-auth"
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

# Stop and disable services
stop_services() {
    print_info "Stopping services..."
    
    # Stop service if running
    if systemctl is-active --quiet oidc-auth-broker.service; then
        systemctl stop oidc-auth-broker.service
        print_info "Service stopped"
    fi
    
    # Disable service
    if systemctl is-enabled --quiet oidc-auth-broker.service; then
        systemctl disable oidc-auth-broker.service
        print_info "Service disabled"
    fi
    
    # Remove systemd service file
    if [[ -f "$SYSTEMD_DIR/oidc-auth-broker.service" ]]; then
        rm -f "$SYSTEMD_DIR/oidc-auth-broker.service"
        print_info "Systemd service file removed"
    fi
    
    # Reload systemd
    systemctl daemon-reload
}

# Remove PAM configuration
remove_pam_config() {
    print_info "Removing PAM configuration..."
    
    # Backup current PAM configuration
    if [[ -f "/etc/pam.d/sshd" ]]; then
        cp "/etc/pam.d/sshd" "/etc/pam.d/sshd.backup.uninstall.$(date +%Y%m%d-%H%M%S)"
    fi
    
    # Remove OIDC PAM from SSH configuration
    if grep -q "pam_oidc.so" /etc/pam.d/sshd 2>/dev/null; then
        sed -i '/pam_oidc.so/d' /etc/pam.d/sshd
        sed -i '/# OIDC PAM Authentication/d' /etc/pam.d/sshd
        print_info "OIDC PAM removed from SSH configuration"
    fi
    
    # Restore backup if needed
    if [[ -f "/etc/pam.d/sshd.backup.uninstall.$(date +%Y%m%d-%H%M%S)" ]]; then
        print_info "PAM configuration backed up"
    fi
}

# Remove binaries
remove_binaries() {
    print_info "Removing binaries..."
    
    # Remove binaries
    if [[ -f "$INSTALL_DIR/oidc-auth-broker" ]]; then
        rm -f "$INSTALL_DIR/oidc-auth-broker"
        print_info "Broker binary removed"
    fi
    
    if [[ -f "$INSTALL_DIR/oidc-pam-helper" ]]; then
        rm -f "$INSTALL_DIR/oidc-pam-helper"
        print_info "Helper binary removed"
    fi
    
    if [[ -f "$PAM_DIR/pam_oidc.so" ]]; then
        rm -f "$PAM_DIR/pam_oidc.so"
        print_info "PAM module removed"
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
            rm -rf "$CONFIG_DIR"
            print_info "Configuration directory removed"
        fi
    else
        print_info "Configuration directory preserved"
    fi
    
    # Ask user about log removal
    read -p "Remove log directory $LOG_DIR? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ -d "$LOG_DIR" ]]; then
            rm -rf "$LOG_DIR"
            print_info "Log directory removed"
        fi
    else
        print_info "Log directory preserved"
    fi
    
    # Remove runtime directory
    if [[ -d "$RUN_DIR" ]]; then
        rm -rf "$RUN_DIR"
        print_info "Runtime directory removed"
    fi
}

# Remove user
remove_user() {
    print_info "Removing user..."
    
    # Ask user about user removal
    read -p "Remove oidc-auth user? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if id "oidc-auth" &>/dev/null; then
            userdel oidc-auth
            print_info "User oidc-auth removed"
        fi
    else
        print_info "User oidc-auth preserved"
    fi
}

# Clean up temporary files
cleanup() {
    print_info "Cleaning up temporary files..."
    
    # Remove any temporary files
    rm -f /tmp/oidc-auth-*
    rm -f /tmp/pam_oidc-*
    
    print_info "Cleanup completed"
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
    echo "- PAM module from $PAM_DIR"
    echo "- Systemd service"
    echo "- PAM configuration (backed up)"
    echo ""
    echo "Preserved (if chosen):"
    echo "- Configuration: $CONFIG_DIR"
    echo "- Logs: $LOG_DIR"
    echo "- User: oidc-auth"
    echo ""
    echo "Manual cleanup may be required for:"
    echo "- Custom PAM configurations"
    echo "- SSH configuration changes"
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
    remove_pam_config
    remove_binaries
    remove_config
    remove_user
    cleanup
    print_summary
    
    print_info "Uninstallation completed successfully!"
}

# Run main function
main "$@"