# OIDC PAM SSH Server Test Project

This is a dummy SSH server project for testing the OIDC PAM authentication system. It provides a complete, isolated environment to validate SSH authentication with OIDC integration.

## Overview

This test project creates a containerized SSH server that:
- Uses the OIDC PAM authentication system
- Provides a realistic testing environment
- Includes comprehensive test scenarios
- Validates the complete authentication flow

## Prerequisites

- Docker and Docker Compose
- OIDC PAM authentication system running
- Keycloak test environment (optional)

## Quick Start

### 1. Start the Test Environment

```bash
# Start SSH server with OIDC PAM
docker-compose up -d

# Check status
docker-compose ps
```

### 2. Test SSH Authentication

```bash
# Test with OIDC authentication
ssh testuser@localhost -p 2222

# Test with different users
ssh admin@localhost -p 2222
ssh developer@localhost -p 2222
```

### 3. Run Automated Tests

```bash
# Run all tests
./run-tests.sh

# Run specific test suite
./run-tests.sh --suite authentication
./run-tests.sh --suite authorization
./run-tests.sh --suite integration
```

## Architecture

### Components

1. **SSH Server Container**: Ubuntu-based container with OpenSSH and OIDC PAM
2. **OIDC Broker**: Authentication service integration
3. **Test Users**: Pre-configured test users with different roles
4. **Test Scripts**: Automated validation scripts

### Network Configuration

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SSH Client    │────│   SSH Server    │────│   OIDC Broker   │
│   (localhost)   │    │   (port 2222)   │    │   (port 8080)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                │
                       ┌─────────────────┐
                       │   Keycloak      │
                       │   (port 8080)   │
                       └─────────────────┘
```

## Configuration

### Test Users

The SSH server includes pre-configured test users:

| Username | Role | Groups | SSH Access |
|----------|------|---------|------------|
| testuser | Standard User | users, ssh-users | Yes |
| admin | Administrator | users, admin, ssh-users | Yes |
| developer | Developer | users, developers, ssh-users | Yes |
| contractor | Contractor | contractors, ssh-users | Limited |
| service | Service Account | service-accounts | No Interactive |

### SSH Configuration

The SSH server is configured with:
- PAM authentication enabled
- OIDC PAM module integrated
- Public key authentication disabled (for testing)
- Comprehensive logging enabled

### PAM Configuration

```bash
# /etc/pam.d/sshd
auth    sufficient  pam_oidc.so config=/etc/oidc-auth/broker.yaml service=ssh debug
auth    requisite   pam_deny.so
auth    required    pam_unix.so try_first_pass

account sufficient  pam_oidc.so config=/etc/oidc-auth/broker.yaml
account required    pam_unix.so
account required    pam_access.so

session required    pam_unix.so
session optional    pam_oidc.so config=/etc/oidc-auth/broker.yaml
session required    pam_systemd.so
```

## Test Scenarios

### 1. Authentication Tests

#### Basic Authentication
```bash
# Test successful authentication
ssh testuser@localhost -p 2222

# Expected: Device flow initiated, user authenticates, SSH session established
```

#### Failed Authentication
```bash
# Test with invalid user
ssh invaliduser@localhost -p 2222

# Expected: Authentication fails, connection denied
```

#### Group-based Access
```bash
# Test admin access
ssh admin@localhost -p 2222

# Test contractor access (limited hours)
ssh contractor@localhost -p 2222
```

### 2. Authorization Tests

#### Command Execution
```bash
# Test basic commands
ssh testuser@localhost -p 2222 "whoami"
ssh testuser@localhost -p 2222 "ls -la"

# Test restricted commands
ssh contractor@localhost -p 2222 "sudo whoami"
# Expected: Permission denied
```

#### File Access
```bash
# Test file access permissions
ssh testuser@localhost -p 2222 "cat /etc/passwd"
ssh testuser@localhost -p 2222 "cat /etc/shadow"
# Expected: Permission denied for /etc/shadow
```

### 3. Integration Tests

#### OIDC Provider Connectivity
```bash
# Test with OIDC provider down
docker-compose stop keycloak
ssh testuser@localhost -p 2222
# Expected: Authentication fails with provider error
```

#### Broker Connectivity
```bash
# Test with broker down
docker-compose stop oidc-broker
ssh testuser@localhost -p 2222
# Expected: Authentication fails with broker error
```

#### Network Isolation
```bash
# Test from different networks
ssh testuser@172.16.0.100 -p 2222  # Allowed network
ssh testuser@10.0.0.100 -p 2222     # Denied network
```

## Monitoring and Logging

### Log Files

- **SSH Logs**: `/var/log/ssh-server/auth.log`
- **OIDC Logs**: `/var/log/ssh-server/oidc.log`
- **Audit Logs**: `/var/log/ssh-server/audit.log`

### Monitoring Commands

```bash
# Monitor SSH authentication attempts
docker-compose exec ssh-server tail -f /var/log/auth.log

# Monitor OIDC authentication flow
docker-compose exec ssh-server tail -f /var/log/oidc-auth/broker.log

# Monitor system activity
docker-compose exec ssh-server journalctl -f
```

## Troubleshooting

### Common Issues

#### SSH Connection Refused
```bash
# Check SSH service status
docker-compose exec ssh-server systemctl status ssh

# Check SSH configuration
docker-compose exec ssh-server sshd -T
```

#### OIDC Authentication Failures
```bash
# Check OIDC broker connectivity
docker-compose exec ssh-server curl -v http://oidc-broker:8080/health

# Check PAM configuration
docker-compose exec ssh-server cat /etc/pam.d/sshd
```

#### Permission Denied
```bash
# Check user permissions
docker-compose exec ssh-server getent passwd testuser

# Check group membership
docker-compose exec ssh-server groups testuser
```

### Debug Mode

Enable debug logging:

```bash
# Edit docker-compose.yml
environment:
  - OIDC_LOG_LEVEL=debug
  - SSH_LOG_LEVEL=debug

# Restart services
docker-compose restart
```

## Performance Testing

### Load Testing

```bash
# Run concurrent SSH connections
./load-test.sh --connections 50 --duration 60

# Test authentication performance
./auth-performance.sh --users 100 --iterations 10
```

### Metrics Collection

```bash
# Collect authentication metrics
./collect-metrics.sh --duration 300

# Generate performance report
./generate-report.sh --output ssh-performance.html
```

## Security Testing

### Penetration Testing

```bash
# Test SSH brute force protection
./security-tests.sh --test bruteforce

# Test authentication bypass attempts
./security-tests.sh --test bypass

# Test privilege escalation
./security-tests.sh --test privesc
```

### Vulnerability Scanning

```bash
# Scan SSH configuration
./vuln-scan.sh --target ssh-config

# Scan OIDC integration
./vuln-scan.sh --target oidc-integration
```

## CI/CD Integration

### Automated Testing

```yaml
# .github/workflows/ssh-server-test.yml
name: SSH Server Test
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Start test environment
        run: |
          cd test-projects/ssh-server
          docker-compose up -d
      - name: Run tests
        run: |
          cd test-projects/ssh-server
          ./run-tests.sh --ci
      - name: Collect logs
        if: always()
        run: |
          cd test-projects/ssh-server
          ./collect-logs.sh
```

### Test Reporting

```bash
# Generate test report
./generate-test-report.sh --format junit --output test-results.xml

# Generate coverage report
./generate-coverage-report.sh --format html --output coverage.html
```

## Customization

### Adding Test Users

1. Edit `docker/ssh-server/users.txt`
2. Add user to OIDC provider
3. Update group mappings
4. Rebuild container

### Modifying Test Scenarios

1. Edit test scripts in `tests/` directory
2. Update configuration files
3. Add new test cases
4. Update documentation

### Custom PAM Configuration

1. Edit `docker/ssh-server/pam.d/sshd`
2. Update OIDC broker configuration
3. Test configuration changes
4. Document modifications

## Best Practices

### Testing Guidelines

1. **Isolation**: Each test should be independent
2. **Cleanup**: Always clean up test resources
3. **Validation**: Verify all assertions
4. **Logging**: Capture comprehensive logs
5. **Documentation**: Document test scenarios

### Security Considerations

1. **Test Data**: Use non-sensitive test data only
2. **Network**: Isolate test networks
3. **Credentials**: Use test credentials only
4. **Cleanup**: Remove test artifacts
5. **Monitoring**: Monitor test activities

## Contributing

### Adding New Tests

1. Create test script in `tests/` directory
2. Follow naming convention: `test-<scenario>.sh`
3. Include setup and cleanup
4. Update test suite configuration
5. Document test purpose and expected results

### Reporting Issues

1. Provide detailed error messages
2. Include log files
3. Specify test environment
4. Provide reproduction steps
5. Include expected vs actual results

## Support

For issues with this test project:
- Check troubleshooting guide
- Review log files
- Verify configuration
- Contact development team

## License

This test project is part of the OIDC PAM authentication system and is licensed under the MIT License.