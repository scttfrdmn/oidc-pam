#!/bin/bash

# Test: Basic OIDC Authentication
# This test validates basic OIDC authentication flow for SSH

set -e

# Test configuration
TEST_NAME="authentication-basic"
TEST_DESCRIPTION="Basic OIDC authentication test"

# Import test utilities
source "$(dirname "$0")/test-utils.sh"

# Test setup
setup_test() {
    log_info "Setting up $TEST_DESCRIPTION"
    
    # Verify SSH server is running
    if ! nc -z "$SSH_HOST" "$SSH_PORT"; then
        log_error "SSH server is not running"
        exit 1
    fi
    
    # Verify OIDC broker is running
    if ! curl -sf "$OIDC_BROKER_URL/health" > /dev/null 2>&1; then
        log_error "OIDC broker is not running"
        exit 1
    fi
    
    log_success "Test setup completed"
}

# Test: SSH connection attempt
test_ssh_connection() {
    log_info "Testing SSH connection attempt"
    
    # Test SSH connectivity without authentication
    if timeout 10 ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=no \
        -p "$SSH_PORT" testuser@"$SSH_HOST" exit 2>/dev/null; then
        log_error "SSH connection succeeded without authentication (this should not happen)"
        return 1
    fi
    
    log_success "SSH connection properly requires authentication"
    return 0
}

# Test: OIDC authentication flow initiation
test_oidc_flow_initiation() {
    log_info "Testing OIDC authentication flow initiation"
    
    # Attempt SSH connection and check for OIDC device flow
    local ssh_output
    ssh_output=$(timeout 30 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
        -p "$SSH_PORT" testuser@"$SSH_HOST" exit 2>&1 || true)
    
    # Check if device flow was initiated
    if echo "$ssh_output" | grep -q "Device code\|User code\|Verification"; then
        log_success "OIDC device flow initiated successfully"
        return 0
    fi
    
    log_error "OIDC device flow was not initiated"
    log_error "SSH output: $ssh_output"
    return 1
}

# Test: Authentication with invalid user
test_invalid_user() {
    log_info "Testing authentication with invalid user"
    
    # Attempt SSH connection with invalid user
    local ssh_output
    ssh_output=$(timeout 10 ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=no \
        -p "$SSH_PORT" invaliduser@"$SSH_HOST" exit 2>&1 || true)
    
    # Check if authentication was rejected
    if echo "$ssh_output" | grep -q "Permission denied\|Authentication failed"; then
        log_success "Invalid user authentication properly rejected"
        return 0
    fi
    
    log_error "Invalid user authentication was not rejected"
    log_error "SSH output: $ssh_output"
    return 1
}

# Test: PAM module integration
test_pam_integration() {
    log_info "Testing PAM module integration"
    
    # Check if PAM module is loaded
    if docker-compose exec -T ssh-server test -f /lib/security/pam_oidc.so; then
        log_success "PAM OIDC module is present"
    else
        log_error "PAM OIDC module is not present"
        return 1
    fi
    
    # Check PAM configuration
    if docker-compose exec -T ssh-server grep -q "pam_oidc.so" /etc/pam.d/sshd; then
        log_success "PAM OIDC module is configured"
    else
        log_error "PAM OIDC module is not configured"
        return 1
    fi
    
    return 0
}

# Test: SSH server logs
test_ssh_logs() {
    log_info "Testing SSH server logs"
    
    # Check if SSH logs are being generated
    if docker-compose exec -T ssh-server test -f /var/log/auth.log; then
        log_success "SSH logs are being generated"
    else
        log_warning "SSH logs are not being generated"
    fi
    
    # Check for recent SSH activity
    local recent_logs
    recent_logs=$(docker-compose exec -T ssh-server tail -10 /var/log/auth.log 2>/dev/null || echo "No logs")
    
    if [ "$recent_logs" != "No logs" ]; then
        log_success "SSH activity is being logged"
    else
        log_warning "No recent SSH activity in logs"
    fi
    
    return 0
}

# Test: OIDC broker connectivity
test_broker_connectivity() {
    log_info "Testing OIDC broker connectivity from SSH server"
    
    # Test connectivity from SSH server to OIDC broker
    if docker-compose exec -T ssh-server curl -sf "$OIDC_BROKER_URL/health" > /dev/null 2>&1; then
        log_success "SSH server can reach OIDC broker"
    else
        log_error "SSH server cannot reach OIDC broker"
        return 1
    fi
    
    # Test OIDC broker health endpoint
    local health_status
    health_status=$(docker-compose exec -T ssh-server curl -s "$OIDC_BROKER_URL/health" | grep -o '"status":"[^"]*"' || echo "unknown")
    
    if [[ $health_status == *"healthy"* ]] || [[ $health_status == *"ok"* ]]; then
        log_success "OIDC broker reports healthy status"
    else
        log_warning "OIDC broker health status: $health_status"
    fi
    
    return 0
}

# Test cleanup
cleanup_test() {
    log_info "Cleaning up $TEST_DESCRIPTION"
    
    # Kill any remaining SSH processes
    pkill -f "ssh.*$SSH_HOST" || true
    
    log_success "Test cleanup completed"
}

# Main test execution
main() {
    log_info "Starting $TEST_DESCRIPTION"
    
    # Set up signal handlers
    trap cleanup_test EXIT INT TERM
    
    # Run test setup
    setup_test
    
    # Run individual tests
    local failed=0
    
    test_ssh_connection || ((failed++))
    test_oidc_flow_initiation || ((failed++))
    test_invalid_user || ((failed++))
    test_pam_integration || ((failed++))
    test_ssh_logs || ((failed++))
    test_broker_connectivity || ((failed++))
    
    # Report results
    if [ $failed -eq 0 ]; then
        log_success "All tests passed for $TEST_DESCRIPTION"
        exit 0
    else
        log_error "$failed test(s) failed for $TEST_DESCRIPTION"
        exit 1
    fi
}

# Run main function
main "$@"