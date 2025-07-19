#!/bin/bash

# OIDC PAM SSH Server Test Runner
# This script runs comprehensive tests for the SSH server with OIDC authentication

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$SCRIPT_DIR/tests"
RESULTS_DIR="$SCRIPT_DIR/results"
LOGS_DIR="$SCRIPT_DIR/logs"
CONFIG_DIR="$SCRIPT_DIR/config"

# Test configuration
SSH_HOST="localhost"
SSH_PORT="2222"
OIDC_BROKER_URL="http://localhost:8080"
KEYCLOAK_URL="http://localhost:8081"
TEST_TIMEOUT=300
PARALLEL_TESTS=false
VERBOSE=false
CI_MODE=false

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    --suite SUITE       Run specific test suite (authentication, authorization, integration, security, performance)
    --test TEST         Run specific test
    --parallel          Run tests in parallel
    --verbose           Enable verbose output
    --ci                Run in CI mode (non-interactive)
    --timeout SECONDS   Set test timeout (default: 300)
    --help              Show this help message

Test Suites:
    authentication     Basic authentication tests
    authorization      Authorization and access control tests
    integration        Integration tests with OIDC provider
    security           Security and vulnerability tests
    performance        Performance and load tests
    all                Run all test suites (default)

Examples:
    $0                                 # Run all tests
    $0 --suite authentication          # Run authentication tests only
    $0 --test test-basic-auth          # Run specific test
    $0 --parallel --verbose            # Run tests in parallel with verbose output
    $0 --ci                            # Run in CI mode
EOF
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Initialize test environment
init_test_environment() {
    log_info "Initializing test environment..."
    
    # Create directories
    mkdir -p "$RESULTS_DIR" "$LOGS_DIR"
    
    # Clean up previous results
    rm -rf "$RESULTS_DIR"/*
    
    # Set up test environment variables
    export SSH_HOST
    export SSH_PORT
    export OIDC_BROKER_URL
    export KEYCLOAK_URL
    export TEST_TIMEOUT
    export RESULTS_DIR
    export LOGS_DIR
    export VERBOSE
    export CI_MODE
    
    # Create test results file
    echo "Test Results - $(date)" > "$RESULTS_DIR/test-results.txt"
    echo "=================================" >> "$RESULTS_DIR/test-results.txt"
    echo "" >> "$RESULTS_DIR/test-results.txt"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if Docker Compose is available
    if ! command -v docker-compose &> /dev/null; then
        log_error "docker-compose is not installed"
        exit 1
    fi
    
    # Check if services are running
    if ! docker-compose ps | grep -q "Up"; then
        log_error "Test environment is not running. Please start with: docker-compose up -d"
        exit 1
    fi
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    
    # Wait for SSH server
    local retries=0
    while ! nc -z "$SSH_HOST" "$SSH_PORT" && [ $retries -lt 30 ]; do
        log_info "Waiting for SSH server..."
        sleep 5
        ((retries++))
    done
    
    if [ $retries -ge 30 ]; then
        log_error "SSH server is not responding"
        exit 1
    fi
    
    # Wait for OIDC broker
    retries=0
    while ! curl -sf "$OIDC_BROKER_URL/health" > /dev/null 2>&1 && [ $retries -lt 30 ]; do
        log_info "Waiting for OIDC broker..."
        sleep 5
        ((retries++))
    done
    
    if [ $retries -ge 30 ]; then
        log_error "OIDC broker is not responding"
        exit 1
    fi
    
    # Wait for Keycloak
    retries=0
    while ! curl -sf "$KEYCLOAK_URL/health/ready" > /dev/null 2>&1 && [ $retries -lt 60 ]; do
        log_info "Waiting for Keycloak..."
        sleep 5
        ((retries++))
    done
    
    if [ $retries -ge 60 ]; then
        log_warning "Keycloak is not responding (some tests may fail)"
    fi
    
    log_success "Prerequisites check completed"
}

# Run a single test
run_test() {
    local test_file="$1"
    local test_name
    test_name=$(basename "$test_file" .sh)
    
    log_info "Running test: $test_name"
    
    ((TOTAL_TESTS++))
    
    # Create test log file
    local test_log="$LOGS_DIR/${test_name}.log"
    
    # Set up test environment
    export TEST_NAME="$test_name"
    export TEST_LOG="$test_log"
    
    # Run the test
    local start_time
    start_time=$(date +%s)
    
    if timeout "$TEST_TIMEOUT" bash "$test_file" > "$test_log" 2>&1; then
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        log_success "Test $test_name passed (${duration}s)"
        echo "PASS: $test_name (${duration}s)" >> "$RESULTS_DIR/test-results.txt"
        ((PASSED_TESTS++))
        return 0
    else
        local exit_code=$?
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        if [ $exit_code -eq 124 ]; then
            log_error "Test $test_name timed out after ${TEST_TIMEOUT}s"
            echo "TIMEOUT: $test_name (${TEST_TIMEOUT}s)" >> "$RESULTS_DIR/test-results.txt"
        else
            log_error "Test $test_name failed (${duration}s)"
            echo "FAIL: $test_name (${duration}s)" >> "$RESULTS_DIR/test-results.txt"
            
            # Show error details if verbose
            if [ "$VERBOSE" = true ]; then
                echo "Error details:"
                tail -10 "$test_log"
            fi
        fi
        
        ((FAILED_TESTS++))
        return 1
    fi
}

# Run test suite
run_test_suite() {
    local suite="$1"
    
    log_info "Running test suite: $suite"
    
    # Find test files for the suite
    local test_files
    if [ "$suite" = "all" ]; then
        test_files=$(find "$TESTS_DIR" -name "test-*.sh" | sort)
    else
        test_files=$(find "$TESTS_DIR" -name "test-${suite}-*.sh" | sort)
    fi
    
    if [ -z "$test_files" ]; then
        log_warning "No tests found for suite: $suite"
        return 0
    fi
    
    # Run tests
    if [ "$PARALLEL_TESTS" = true ]; then
        # Run tests in parallel
        log_info "Running tests in parallel..."
        
        local pids=()
        for test_file in $test_files; do
            run_test "$test_file" &
            pids+=($!)
        done
        
        # Wait for all tests to complete
        for pid in "${pids[@]}"; do
            wait "$pid"
        done
    else
        # Run tests sequentially
        for test_file in $test_files; do
            run_test "$test_file"
        done
    fi
}

# Run specific test
run_specific_test() {
    local test_name="$1"
    local test_file="$TESTS_DIR/${test_name}.sh"
    
    if [ ! -f "$test_file" ]; then
        log_error "Test not found: $test_name"
        log_info "Available tests:"
        find "$TESTS_DIR" -name "test-*.sh" -exec basename {} .sh \; | sort
        exit 1
    fi
    
    run_test "$test_file"
}

# Generate test report
generate_test_report() {
    log_info "Generating test report..."
    
    # Create summary
    local report_file="$RESULTS_DIR/test-report.html"
    local summary_file="$RESULTS_DIR/test-summary.txt"
    
    # Text summary
    cat > "$summary_file" << EOF
Test Summary - $(date)
======================

Total Tests: $TOTAL_TESTS
Passed: $PASSED_TESTS
Failed: $FAILED_TESTS
Skipped: $SKIPPED_TESTS

Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%

Test Results:
$(cat "$RESULTS_DIR/test-results.txt")
EOF
    
    # HTML report
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>OIDC PAM SSH Server Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .passed { color: green; }
        .failed { color: red; }
        .timeout { color: orange; }
        .test-results { margin-top: 20px; }
        .test-result { padding: 10px; margin: 5px 0; border-radius: 3px; }
        .test-passed { background-color: #d4edda; }
        .test-failed { background-color: #f8d7da; }
        .test-timeout { background-color: #fff3cd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>OIDC PAM SSH Server Test Report</h1>
        <p>Generated: $(date)</p>
    </div>
    
    <div class="summary">
        <h2>Test Summary</h2>
        <p>Total Tests: <strong>$TOTAL_TESTS</strong></p>
        <p>Passed: <strong class="passed">$PASSED_TESTS</strong></p>
        <p>Failed: <strong class="failed">$FAILED_TESTS</strong></p>
        <p>Skipped: <strong>$SKIPPED_TESTS</strong></p>
        <p>Success Rate: <strong>$(( PASSED_TESTS * 100 / TOTAL_TESTS ))%</strong></p>
    </div>
    
    <div class="test-results">
        <h2>Test Results</h2>
EOF
    
    # Add test results to HTML
    while read -r line; do
        if [[ $line =~ ^PASS: ]]; then
            echo "        <div class=\"test-result test-passed\">✓ $line</div>" >> "$report_file"
        elif [[ $line =~ ^FAIL: ]]; then
            echo "        <div class=\"test-result test-failed\">✗ $line</div>" >> "$report_file"
        elif [[ $line =~ ^TIMEOUT: ]]; then
            echo "        <div class=\"test-result test-timeout\">⏱ $line</div>" >> "$report_file"
        fi
    done < "$RESULTS_DIR/test-results.txt"
    
    cat >> "$report_file" << EOF
    </div>
</body>
</html>
EOF
    
    log_success "Test report generated: $report_file"
    log_success "Test summary generated: $summary_file"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."
    
    # Kill any remaining background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Generate final report
    generate_test_report
    
    # Display summary
    echo ""
    echo "Test Summary:"
    echo "============="
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo "Skipped: $SKIPPED_TESTS"
    
    if [ $TOTAL_TESTS -gt 0 ]; then
        echo "Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
    fi
    
    # Exit with appropriate code
    if [ $FAILED_TESTS -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Main function
main() {
    local suite="all"
    local specific_test=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --suite)
                suite="$2"
                shift 2
                ;;
            --test)
                specific_test="$2"
                shift 2
                ;;
            --parallel)
                PARALLEL_TESTS=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --ci)
                CI_MODE=true
                shift
                ;;
            --timeout)
                TEST_TIMEOUT="$2"
                shift 2
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Initialize test environment
    init_test_environment
    
    # Check prerequisites
    check_prerequisites
    
    # Run tests
    if [ -n "$specific_test" ]; then
        run_specific_test "$specific_test"
    else
        run_test_suite "$suite"
    fi
}

# Run main function
main "$@"