#!/bin/bash

# Test Utilities for OIDC PAM SSH Server Tests
# This file contains common utility functions for tests

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test user credentials
TEST_USERS=("testuser" "admin" "developer" "contractor")
TEST_PASSWORDS=("password123" "password123" "password123" "password123")

# SSH utilities
ssh_test_connection() {
    local user="$1"
    local host="$2"
    local port="$3"
    local timeout="${4:-10}"
    
    timeout "$timeout" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
        -o BatchMode=yes -p "$port" "$user@$host" exit 2>/dev/null
}

ssh_test_command() {
    local user="$1"
    local host="$2"
    local port="$3"
    local command="$4"
    local timeout="${5:-10}"
    
    timeout "$timeout" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
        -o BatchMode=yes -p "$port" "$user@$host" "$command" 2>/dev/null
}

# OIDC utilities
check_oidc_broker() {
    local url="$1"
    
    curl -sf "$url/health" > /dev/null 2>&1
}

get_oidc_status() {
    local url="$1"
    
    curl -s "$url/health" 2>/dev/null | grep -o '"status":"[^"]*"' | cut -d'"' -f4
}

# Docker utilities
docker_exec() {
    local service="$1"
    local command="$2"
    
    docker-compose exec -T "$service" bash -c "$command"
}

docker_logs() {
    local service="$1"
    local lines="${2:-10}"
    
    docker-compose logs --tail="$lines" "$service"
}

# Wait utilities
wait_for_service() {
    local host="$1"
    local port="$2"
    local timeout="${3:-60}"
    local interval="${4:-5}"
    
    local elapsed=0
    while ! nc -z "$host" "$port" && [ $elapsed -lt $timeout ]; do
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done
    
    if [ $elapsed -ge $timeout ]; then
        return 1
    fi
    
    return 0
}

wait_for_http_service() {
    local url="$1"
    local timeout="${2:-60}"
    local interval="${3:-5}"
    
    local elapsed=0
    while ! curl -sf "$url" > /dev/null 2>&1 && [ $elapsed -lt $timeout ]; do
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done
    
    if [ $elapsed -ge $timeout ]; then
        return 1
    fi
    
    return 0
}

# Authentication utilities
simulate_device_flow() {
    local broker_url="$1"
    local client_id="$2"
    local username="$3"
    local password="$4"
    
    # This would normally interact with the OIDC provider
    # For testing, we'll simulate the flow
    log_info "Simulating device flow for user: $username"
    
    # In a real scenario, this would:
    # 1. Initiate device flow
    # 2. Get device code and user code
    # 3. Direct user to verification URL
    # 4. Poll for token
    # 5. Return access token
    
    # For testing, we'll just return a mock response
    echo "mock_access_token"
}

# Validation utilities
validate_ssh_config() {
    local service="$1"
    
    # Check SSH daemon configuration
    if ! docker_exec "$service" "sshd -t"; then
        log_error "SSH daemon configuration is invalid"
        return 1
    fi
    
    # Check if SSH is listening
    if ! docker_exec "$service" "netstat -tuln | grep -q :22"; then
        log_error "SSH daemon is not listening on port 22"
        return 1
    fi
    
    return 0
}

validate_pam_config() {
    local service="$1"
    
    # Check if PAM OIDC module exists
    if ! docker_exec "$service" "test -f /lib/security/pam_oidc.so"; then
        log_error "PAM OIDC module not found"
        return 1
    fi
    
    # Check PAM configuration
    if ! docker_exec "$service" "grep -q pam_oidc.so /etc/pam.d/sshd"; then
        log_error "PAM OIDC module not configured for SSH"
        return 1
    fi
    
    return 0
}

validate_oidc_config() {
    local service="$1"
    
    # Check if OIDC configuration exists
    if ! docker_exec "$service" "test -f /etc/oidc-auth/broker.yaml"; then
        log_error "OIDC configuration not found"
        return 1
    fi
    
    # Check configuration permissions
    local perms
    perms=$(docker_exec "$service" "stat -c %a /etc/oidc-auth/broker.yaml")
    if [ "$perms" != "640" ]; then
        log_warning "OIDC configuration permissions are not secure: $perms"
    fi
    
    return 0
}

# Network utilities
test_network_connectivity() {
    local from_service="$1"
    local to_host="$2"
    local to_port="$3"
    
    if docker_exec "$from_service" "nc -z $to_host $to_port"; then
        return 0
    else
        return 1
    fi
}

test_http_connectivity() {
    local from_service="$1"
    local to_url="$2"
    
    if docker_exec "$from_service" "curl -sf $to_url > /dev/null"; then
        return 0
    else
        return 1
    fi
}

# Log utilities
extract_logs() {
    local service="$1"
    local log_file="$2"
    local output_file="$3"
    
    docker_exec "$service" "cat $log_file" > "$output_file" 2>/dev/null || true
}

search_logs() {
    local service="$1"
    local log_file="$2"
    local pattern="$3"
    
    docker_exec "$service" "grep '$pattern' $log_file" 2>/dev/null || true
}

# Security utilities
check_file_permissions() {
    local service="$1"
    local file_path="$2"
    local expected_perms="$3"
    
    local actual_perms
    actual_perms=$(docker_exec "$service" "stat -c %a $file_path" 2>/dev/null || echo "000")
    
    if [ "$actual_perms" = "$expected_perms" ]; then
        return 0
    else
        log_warning "File $file_path has permissions $actual_perms, expected $expected_perms"
        return 1
    fi
}

check_user_groups() {
    local service="$1"
    local username="$2"
    local expected_groups="$3"
    
    local actual_groups
    actual_groups=$(docker_exec "$service" "groups $username" 2>/dev/null || echo "")
    
    for group in $expected_groups; do
        if ! echo "$actual_groups" | grep -q "$group"; then
            log_warning "User $username is not in group $group"
            return 1
        fi
    done
    
    return 0
}

# Performance utilities
measure_authentication_time() {
    local user="$1"
    local host="$2"
    local port="$3"
    
    local start_time
    local end_time
    
    start_time=$(date +%s.%N)
    
    # Attempt authentication (will fail, but measures time to failure)
    timeout 30 ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
        -o BatchMode=yes -p "$port" "$user@$host" exit 2>/dev/null || true
    
    end_time=$(date +%s.%N)
    
    # Calculate duration
    local duration
    duration=$(echo "$end_time - $start_time" | bc -l)
    
    echo "$duration"
}

# Test result utilities
record_test_result() {
    local test_name="$1"
    local status="$2"
    local message="$3"
    local duration="$4"
    
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] $test_name: $status - $message (${duration}s)" >> "$TEST_LOG"
}

# Cleanup utilities
cleanup_ssh_connections() {
    # Kill any remaining SSH processes
    pkill -f "ssh.*$SSH_HOST" 2>/dev/null || true
    
    # Clean up SSH known hosts
    ssh-keygen -R "[$SSH_HOST]:$SSH_PORT" 2>/dev/null || true
}

cleanup_test_files() {
    local test_dir="$1"
    
    # Remove temporary test files
    find "$test_dir" -name "*.tmp" -delete 2>/dev/null || true
    find "$test_dir" -name "*.temp" -delete 2>/dev/null || true
}

# Export all functions
export -f log_info log_success log_warning log_error
export -f ssh_test_connection ssh_test_command
export -f check_oidc_broker get_oidc_status
export -f docker_exec docker_logs
export -f wait_for_service wait_for_http_service
export -f simulate_device_flow
export -f validate_ssh_config validate_pam_config validate_oidc_config
export -f test_network_connectivity test_http_connectivity
export -f extract_logs search_logs
export -f check_file_permissions check_user_groups
export -f measure_authentication_time
export -f record_test_result
export -f cleanup_ssh_connections cleanup_test_files