# Universal OIDC Provider Configuration Guide

## Overview

The OIDC PAM solution supports **any OIDC-compliant identity provider** through standard OIDC Discovery mechanisms. This document provides comprehensive configuration examples and guidance for integrating with major identity providers and custom OIDC implementations.

## The Power of OIDC Standards

### Why Any Provider Works
OIDC (OpenID Connect) is a standardized authentication layer built on OAuth 2.0. Every compliant provider exposes the same standard endpoints and capabilities through the **OIDC Discovery** mechanism, making universal support possible with minimal configuration.

### OIDC Discovery Process
```
1. Provider publishes configuration at: {issuer}/.well-known/openid-configuration
2. OIDC PAM fetches this configuration automatically
3. All endpoints, capabilities, and security parameters are discovered
4. Device Flow authentication proceeds using standard protocols
```

This means the host configuration is **remarkably simple** regardless of the identity provider.

## Minimal Configuration Pattern

### Universal Configuration Template
```yaml
# /etc/oidc-auth/broker.yaml - Works with ANY OIDC provider
oidc:
  providers:
    - name: "primary"                           # Friendly name
      issuer: "https://your-provider.com"       # Provider's issuer URL
      client_id: "your-client-id"               # App registration ID
      scopes: ["openid", "email", "groups"]    # Desired claims
      
# Everything else is auto-discovered!
```

### Required Information (Only 3 Things!)
1. **Issuer URL**: The base URL of your OIDC provider
2. **Client ID**: Your application registration identifier
3. **Scopes**: What user information you want to access

That's it! All endpoints, security parameters, and capabilities are discovered automatically.

## Major Provider Configurations

### Okta
```yaml
oidc:
  providers:
    - name: "okta-corporate"
      issuer: "https://company.okta.com"
      client_id: "0oa1b2c3d4e5f6g7h8i9"
      scopes: ["openid", "email", "groups"]
      
      # Optional: Custom user mapping
      user_mapping:
        username_claim: "email"
        groups_claim: "groups"
        name_claim: "name"
```

**Okta App Setup**:
1. Create new "Native Application" in Okta Admin
2. Enable "Device Authorization" grant type
3. Add redirect URI: `http://localhost:8080/callback` (for CLI tools)
4. Copy Client ID to configuration

### Azure Active Directory
```yaml
oidc:
  providers:
    - name: "azure-corporate"
      issuer: "https://login.microsoftonline.com/{tenant-id}/v2.0"
      client_id: "12345678-1234-1234-1234-123456789abc"
      scopes: ["openid", "email", "https://graph.microsoft.com/User.Read", "https://graph.microsoft.com/Group.Read.All"]
      
      user_mapping:
        username_claim: "preferred_username"
        groups_claim: "groups"
        name_claim: "name"
```

**Azure AD App Registration**:
1. Register new application in Azure Portal
2. Set "Allow public client flows" to Yes
3. Add "Device code flow" permission
4. Grant necessary Microsoft Graph permissions
5. Copy Application (client) ID

### Auth0
```yaml
oidc:
  providers:
    - name: "auth0-users"
      issuer: "https://company.auth0.com"
      client_id: "AbC123XyZ789DefGhi"
      scopes: ["openid", "email", "https://company.com/groups"]
      
      user_mapping:
        username_claim: "email"
        groups_claim: "https://company.com/groups"
        name_claim: "name"
```

**Auth0 Application Setup**:
1. Create "Native" application type
2. Enable "Device Code" grant type
3. Configure custom scopes for groups/roles
4. Set up Rules/Actions to include group claims
5. Copy Client ID

### Google Workspace
```yaml
oidc:
  providers:
    - name: "google-workspace"
      issuer: "https://accounts.google.com"
      client_id: "123456789-abc123def456.apps.googleusercontent.com"
      scopes: ["openid", "email", "https://www.googleapis.com/auth/admin.directory.group.readonly"]
      
      user_mapping:
        username_claim: "email"
        groups_claim: "groups"  # Requires custom implementation
        name_claim: "name"
```

**Google Cloud Console Setup**:
1. Create OAuth 2.0 Client ID (Desktop application)
2. Enable required APIs (Admin SDK, etc.)
3. Configure OAuth consent screen
4. Download client configuration

### Keycloak (Self-Hosted)
```yaml
oidc:
  providers:
    - name: "keycloak"
      issuer: "https://keycloak.company.com/realms/master"
      client_id: "oidc-pam-client"
      scopes: ["openid", "email", "roles", "groups"]
      
      user_mapping:
        username_claim: "preferred_username"
        groups_claim: "groups"
        roles_claim: "realm_access.roles"
```

**Keycloak Client Setup**:
1. Create new Client in Keycloak Admin
2. Set Client Protocol to "openid-connect"
3. Set Access Type to "public"
4. Enable "Device Authorization Grant" flow
5. Configure group/role mappers

### Ping Identity
```yaml
oidc:
  providers:
    - name: "ping-identity"
      issuer: "https://auth.pingone.com/{environment-id}"
      client_id: "ping-client-abc123"
      scopes: ["openid", "email", "p1:read:user", "p1:read:userGroup"]
      
      user_mapping:
        username_claim: "email"
        groups_claim: "memberOf"
        name_claim: "name"
```

### Google Cloud Identity / Google Workspace
```yaml
oidc:
  providers:
    - name: "google-workspace"
      issuer: "https://accounts.google.com"
      client_id: "123456789-abc123def456.apps.googleusercontent.com"
      scopes: ["openid", "email", "profile", "https://www.googleapis.com/auth/admin.directory.group.readonly"]
      
      user_mapping:
        username_claim: "email"
        groups_claim: "groups"  # Requires Google Workspace API integration
        name_claim: "name"
        domain_claim: "hd"      # Hosted domain for organization validation
```

**Google Cloud Console Setup**:
1. Create OAuth 2.0 Client ID (Desktop Application type)
2. Enable Admin SDK API for group membership access
3. Configure OAuth consent screen for internal use
4. Device flow is supported by default
5. Copy Client ID to configuration

### Globus Auth (Research Computing)
```yaml
oidc:
  providers:
    - name: "globus-research"
      issuer: "https://auth.globus.org"
      client_id: "your-globus-client-id"
      scopes: ["openid", "email", "profile", "urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships"]
      
      user_mapping:
        username_claim: "preferred_username"
        email_claim: "email"
        groups_claim: "groups"
        organization_claim: "organization"
        institution_claim: "institution"
```

**Globus Developers Console Setup**:
1. Register application at https://developers.globus.org
2. Set application type to "Native Client" 
3. Enable "Device Code" grant type
4. Request groups and profile scopes
5. Configure institutional federation if needed

### Generic OIDC Provider
```yaml
oidc:
  providers:
    - name: "custom-provider"
      issuer: "https://sso.company.com"
      client_id: "ssh-access-client"
      scopes: ["openid", "email", "groups"]
      
      # Optional: Override auto-discovered endpoints if needed
      custom_endpoints:
        device_authorization: "https://sso.company.com/oauth2/device"
        token: "https://sso.company.com/oauth2/token"
        userinfo: "https://sso.company.com/oauth2/userinfo"
        
      user_mapping:
        username_claim: "sub"           # Subject claim
        email_claim: "email"
        groups_claim: "department"      # Custom claim name
        name_claim: "display_name"
```

## Multi-Provider Support

### Research Computing Multi-Provider Configuration
```yaml
oidc:
  providers:
    # Primary research identity via Globus Auth
    - name: "globus-research"
      issuer: "https://auth.globus.org"
      client_id: "research-computing-client"
      scopes: ["openid", "email", "profile", "groups"]
      priority: 1
      user_type: "researcher"
      
    # Google Workspace for institutional access
    - name: "google-institution"
      issuer: "https://accounts.google.com"
      client_id: "university-google-client"
      scopes: ["openid", "email", "profile", "https://www.googleapis.com/auth/admin.directory.group.readonly"]
      priority: 2
      user_type: "institutional"
      
    # Local university SSO
    - name: "university-sso"
      issuer: "https://sso.university.edu"
      client_id: "local-researchers"
      scopes: ["openid", "email", "eduPersonAffiliation", "memberOf"]
      priority: 3
      user_type: "local"
      
    # ORCID for publication/research identity
    - name: "orcid"
      issuer: "https://orcid.org"
      client_id: "orcid-ssh-client"
      scopes: ["openid", "email", "profile"]
      priority: 4
      user_type: "orcid"
      enabled_for_verification_only: true

# Research-specific policies
authentication:
  policies:
    # High-Performance Computing access
    hpc_cluster:
      allowed_providers: ["globus-research", "university-sso"]
      require_groups: ["hpc-users", "active-researchers"]
      require_institutional_affiliation: true
      max_session_duration: "24h"
      require_allocation_verification: true
      
    # Sensitive research data access
    restricted_data:
      allowed_providers: ["globus-research"]
      require_groups: ["data-approved", "pi-sponsored"]
      require_institutional_verification: true
      require_project_membership: true
      max_session_duration: "8h"
      audit_level: "maximum"
      
    # Collaborative research environments
    shared_computing:
      allowed_providers: ["globus-research", "google-institution", "university-sso"]
      require_groups: ["researchers", "collaborators"]
      max_session_duration: "12h"
      allow_cross_institutional: true
      
    # Public datasets and computing
    open_science:
      allowed_providers: ["globus-research", "google-institution", "orcid"]
      max_session_duration: "4h"
      rate_limiting: true
```

### Provider Selection User Experience
```bash
$ ssh alice@prod-server
🔐 Multiple identity providers available:

1) Company Okta (employees) - Recommended
2) Contractor Auth0 (contractors)
3) Partner Azure AD (partners)
4) Emergency Access (break-glass)

Select provider [1]: 1

📱 Authenticating with Company Okta...
Visit: https://company.okta.com/device
Code: WDJB-MJHT
```

## Cloud-Native Auto-Configuration

### AWS Integration
```yaml
# Configuration stored in AWS Parameter Store
cloud:
  provider: "aws"
  auto_discovery: true
  sources:
    - aws_parameter_store:
        region: "us-west-2"
        prefix: "/company/oidc/"
        parameters:
          provider_url: "provider"
          client_id: "client-id"
          scopes: "scopes"
```

```bash
# Store configuration in AWS Parameter Store
aws ssm put-parameter \
  --name "/company/oidc/provider" \
  --value "https://company.okta.com" \
  --type "String"

aws ssm put-parameter \
  --name "/company/oidc/client-id" \
  --value "0oa1b2c3d4e5f6g7h8i9" \
  --type "SecureString"

aws ssm put-parameter \
  --name "/company/oidc/scopes" \
  --value "openid,email,groups" \
  --type "String"
```

### Azure Integration
```yaml
cloud:
  provider: "azure"
  auto_discovery: true
  sources:
    - azure_key_vault:
        vault_name: "company-oidc-vault"
        secrets:
          provider_url: "oidc-provider-url"
          client_id: "oidc-client-id"
          scopes: "oidc-scopes"
```

```bash
# Store configuration in Azure Key Vault
az keyvault secret set \
  --vault-name "company-oidc-vault" \
  --name "oidc-provider-url" \
  --value "https://login.microsoftonline.com/tenant-id/v2.0"

az keyvault secret set \
  --vault-name "company-oidc-vault" \
  --name "oidc-client-id" \
  --value "12345678-1234-1234-1234-123456789abc"
```

### Google Cloud Integration
```yaml
cloud:
  provider: "gcp"
  auto_discovery: true
  sources:
    - gcp_secret_manager:
        project_id: "company-project"
        secrets:
          provider_url: "oidc-provider-url"
          client_id: "oidc-client-id"
          scopes: "oidc-scopes"
```

```bash
# Store configuration in Google Secret Manager
gcloud secrets create oidc-provider-url --data-file=- <<< "https://accounts.google.com"
gcloud secrets create oidc-client-id --data-file=- <<< "123456789-abc.apps.googleusercontent.com"
```

### Environment Variable Configuration
```bash
# Simple environment variable approach
export OIDC_PROVIDER_URL="https://auth.company.com"
export OIDC_CLIENT_ID="your-client-id"
export OIDC_SCOPES="openid,email,groups"

# Broker auto-configures from environment
systemctl start oidc-auth-broker
```

## Advanced Configuration Options

### Custom User Mapping
```yaml
oidc:
  providers:
    - name: "custom-mapping"
      issuer: "https://auth.company.com"
      client_id: "ssh-client"
      scopes: ["openid", "email", "profile", "custom:attributes"]
      
      user_mapping:
        # Map JWT claims to internal user attributes
        username_claim: "preferred_username"    # Use preferred_username instead of email
        email_claim: "email"
        groups_claim: "custom:groups"           # Custom claim for groups
        roles_claim: "custom:roles"             # Custom claim for roles
        department_claim: "custom:department"
        cost_center_claim: "custom:cost_center"
        
        # Transform claims with templates
        username_template: "{{ .username }}@company.com"
        display_name_template: "{{ .given_name }} {{ .family_name }}"
        
        # Group filtering and mapping
        group_prefix: "ssh-"                    # Only include groups starting with "ssh-"
        group_mappings:
          "ssh-production": "production-access"
          "ssh-staging": "staging-access"
          "ssh-development": "developer-access"
```

### Provider-Specific Endpoint Overrides
```yaml
oidc:
  providers:
    - name: "custom-endpoints"
      issuer: "https://auth.company.com"
      client_id: "ssh-client"
      scopes: ["openid", "email", "groups"]
      
      # Override auto-discovered endpoints if needed
      custom_endpoints:
        authorization: "https://auth.company.com/oauth2/authorize"
        token: "https://auth.company.com/oauth2/token"
        device_authorization: "https://auth.company.com/oauth2/device"
        userinfo: "https://auth.company.com/oauth2/userinfo"
        jwks: "https://auth.company.com/oauth2/keys"
        
      # Custom discovery URL if non-standard
      discovery_url: "https://auth.company.com/.well-known/openid_configuration"
      
      # Additional provider-specific settings
      settings:
        audience: "https://api.company.com"     # Required audience for JWT
        max_age: 86400                          # Maximum token age in seconds
        require_auth_time: true                 # Require auth_time claim
        clock_skew_tolerance: 300               # Clock skew tolerance in seconds
```

### Advanced Authentication Policies
```yaml
authentication:
  # Global provider policies
  provider_policies:
    employees:
      trusted_device_required: false
      mfa_required: true
      max_concurrent_sessions: 5
      session_timeout: "8h"
      
    contractors:
      trusted_device_required: true
      mfa_required: true
      max_concurrent_sessions: 2
      session_timeout: "4h"
      require_approval_for: ["production"]
      
    partners:
      trusted_device_required: true
      mfa_required: true
      max_concurrent_sessions: 1
      session_timeout: "2h"
      require_approval_for: ["production", "staging"]
      ip_whitelist: ["203.0.113.0/24", "198.51.100.0/24"]
      
  # Time-based access restrictions
  time_restrictions:
    - providers: ["contractors", "partners"]
      allowed_hours: "06:00-18:00"
      timezone: "America/New_York"
      exceptions: ["emergency-group"]
      
  # Geographic restrictions
  geo_restrictions:
    - providers: ["partners"]
      allowed_countries: ["US", "CA", "GB"]
      blocked_countries: ["CN", "RU", "KP"]
      
  # Risk-based policies
  risk_policies:
    - condition: "provider == 'partners' AND risk_score > 50"
      action: "require_additional_mfa"
    - condition: "unusual_location AND after_hours"
      action: "require_approval"
    - condition: "untrusted_device AND production_access"
      action: "deny"
```

## Installation and Deployment

### Universal One-Line Installation
```bash
# Works with any OIDC provider
curl -sSL https://get.oidc-pam.io/install | \
  OIDC_PROVIDER="https://your-provider.com" \
  OIDC_CLIENT_ID="your-client-id" \
  bash
```

### Provider-Specific Quick Installers
```bash
# Okta
curl -sSL https://get.oidc-pam.io/install | \
  PROVIDER="okta" \
  OKTA_DOMAIN="company.okta.com" \
  CLIENT_ID="0oa1b2c3d4e5f6g7h8i9" \
  bash

# Azure AD
curl -sSL https://get.oidc-pam.io/install | \
  PROVIDER="azure" \
  TENANT_ID="12345678-1234-1234-1234-123456789abc" \
  CLIENT_ID="87654321-4321-4321-4321-210987654321" \
  bash

# Auth0
curl -sSL https://get.oidc-pam.io/install | \
  PROVIDER="auth0" \
  AUTH0_DOMAIN="company.auth0.com" \
  CLIENT_ID="AbC123XyZ789DefGhi" \
  bash

# Google Workspace
curl -sSL https://get.oidc-pam.io/install | \
  PROVIDER="google" \
  CLIENT_ID="123456789-abc.apps.googleusercontent.com" \
  bash

# Google Workspace (for educational institutions)
curl -sSL https://get.oidc-pam.io/install | \
  PROVIDER="google" \
  GOOGLE_CLIENT_ID="123456789-abc.apps.googleusercontent.com" \
  GOOGLE_DOMAIN="university.edu" \
  bash

# Globus Auth (for research computing)
curl -sSL https://get.oidc-pam.io/install | \
  PROVIDER="globus" \
  GLOBUS_CLIENT_ID="your-globus-client-id" \
  bash
```

### Container Deployment
```dockerfile
# Universal container configuration
FROM oidc-pam/broker:latest

# Configuration via environment variables
ENV OIDC_PROVIDER_URL="https://auth.company.com"
ENV OIDC_CLIENT_ID="your-client-id"
ENV OIDC_SCOPES="openid,email,groups"

# Or mount configuration file
COPY broker.yaml /etc/oidc-auth/broker.yaml

EXPOSE 8080
CMD ["oidc-auth-broker"]
```

```bash
# Docker run with environment configuration
docker run -d \
  --name oidc-pam-broker \
  -e OIDC_PROVIDER_URL="https://company.okta.com" \
  -e OIDC_CLIENT_ID="0oa1b2c3d4e5f6g7h8i9" \
  -e OIDC_SCOPES="openid,email,groups" \
  -v /var/run/oidc-auth:/var/run/oidc-auth \
  oidc-pam/broker:latest
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: oidc-pam-broker
spec:
  selector:
    matchLabels:
      app: oidc-pam-broker
  template:
    metadata:
      labels:
        app: oidc-pam-broker
    spec:
      containers:
        - name: broker
          image: oidc-pam/broker:latest
          env:
            - name: OIDC_PROVIDER_URL
              valueFrom:
                secretKeyRef:
                  name: oidc-config
                  key: provider-url
            - name: OIDC_CLIENT_ID
              valueFrom:
                secretKeyRef:
                  name: oidc-config
                  key: client-id
            - name: OIDC_SCOPES
              value: "openid,email,groups"
          volumeMounts:
            - name: broker-socket
              mountPath: /var/run/oidc-auth
      volumes:
        - name: broker-socket
          hostPath:
            path: /var/run/oidc-auth
            type: DirectoryOrCreate

---
apiVersion: v1
kind: Secret
metadata:
  name: oidc-config
type: Opaque
stringData:
  provider-url: "https://company.okta.com"
  client-id: "0oa1b2c3d4e5f6g7h8i9"
```

## Configuration Validation and Testing

### Built-in Configuration Validation
```bash
# Validate configuration syntax and provider connectivity
$ oidc-pam validate-config
✅ Configuration file: /etc/oidc-auth/broker.yaml
✅ OIDC Provider: https://company.okta.com
   • Discovery URL: https://company.okta.com/.well-known/openid-configuration
   • Device Flow Support: ✅ Available
   • Required Scopes: ✅ openid, email, groups
   • JWT Validation: ✅ JWKS endpoint accessible
   • Client ID: ✅ Valid format

✅ Tailscale Integration: Enabled
✅ Network Validation: Working
✅ Audit Logging: Configured

Configuration is valid and ready for use.
```

### Live Authentication Testing
```bash
# Test complete authentication flow
$ oidc-pam test-auth alice@company.com
🔐 Testing authentication flow for alice@company.com...

📋 Provider: company.okta.com
📱 Visit: https://company.okta.com/device
🔑 Code: TEST-1234
⏳ Waiting for authentication...

# After completing authentication on mobile device
✅ Authentication successful!
📧 Email: alice@company.com
👤 Name: Alice Johnson
👥 Groups: developers, production-access, senior-engineers
🔑 SSH key would be provisioned with 4h expiration
📊 Risk score: 15 (low)

Authentication test completed successfully.
```

### Provider Discovery Testing
```bash
# Test OIDC discovery for any provider
$ oidc-pam discover-provider https://auth.company.com
🔍 Discovering OIDC configuration for: https://auth.company.com

✅ Discovery URL: https://auth.company.com/.well-known/openid-configuration
✅ Issuer: https://auth.company.com
✅ Authorization Endpoint: https://auth.company.com/oauth2/authorize
✅ Token Endpoint: https://auth.company.com/oauth2/token
✅ Device Authorization Endpoint: https://auth.company.com/oauth2/device
✅ JWKS Endpoint: https://auth.company.com/oauth2/keys
✅ Userinfo Endpoint: https://auth.company.com/oauth2/userinfo

📋 Supported Grant Types:
   • authorization_code
   • device_code ✅ (Required for OIDC PAM)
   • refresh_token

📋 Supported Scopes:
   • openid ✅
   • email ✅
   • profile ✅
   • groups ✅

🎯 This provider is compatible with OIDC PAM!
```

## Configuration Management Integration

### Ansible Playbook
```yaml
---
- name: Deploy OIDC PAM with provider configuration
  hosts: all
  become: yes
  vars:
    oidc_provider_url: "{{ vault_oidc_provider_url }}"
    oidc_client_id: "{{ vault_oidc_client_id }}"
    
  tasks:
    - name: Install OIDC PAM
      shell: |
        curl -sSL https://get.oidc-pam.io/install | \
          OIDC_PROVIDER="{{ oidc_provider_url }}" \
          OIDC_CLIENT_ID="{{ oidc_client_id }}" \
          bash
      args:
        creates: /usr/local/bin/oidc-auth-broker

    - name: Configure provider-specific settings
      template:
        src: broker.yaml.j2
        dest: /etc/oidc-auth/broker.yaml
        mode: '0600'
      notify: restart oidc-auth-broker

    - name: Validate configuration
      command: oidc-pam validate-config
      register: validation_result
      failed_when: validation_result.rc != 0

  handlers:
    - name: restart oidc-auth-broker
      systemd:
        name: oidc-auth-broker
        state: restarted
```

### Terraform Configuration
```hcl
# Provider-agnostic Terraform module
module "oidc_pam" {
  source = "./modules/oidc-pam"
  
  # Provider configuration
  oidc_provider_url = "https://company.okta.com"
  oidc_client_id    = "0oa1b2c3d4e5f6g7h8i9"
  oidc_scopes       = ["openid", "email", "groups"]
  
  # Deployment configuration
  instance_count = 3
  instance_type  = "t3.medium"
  subnet_ids     = data.aws_subnets.private.ids
  
  # Integration settings
  enable_tailscale_integration = true
  enable_audit_logging        = true
  
  tags = {
    Environment = "production"
    Project     = "zero-trust-access"
  }
}

# Store configuration in cloud-native secret management
resource "aws_ssm_parameter" "oidc_provider" {
  name  = "/company/oidc/provider"
  type  = "String"
  value = "https://company.okta.com"
}

resource "aws_ssm_parameter" "oidc_client_id" {
  name  = "/company/oidc/client-id"
  type  = "SecureString"
  value = "0oa1b2c3d4e5f6g7h8i9"
}
```

## Troubleshooting Common Issues

### Provider Discovery Failures
```bash
# Common issue: Non-standard discovery URL
$ oidc-pam diagnose connectivity https://auth.company.com

❌ Standard discovery failed: https://auth.company.com/.well-known/openid-configuration
🔍 Trying alternative discovery URLs...
✅ Found configuration at: https://auth.company.com/.well-known/openid_configuration

💡 Solution: Add custom discovery URL to configuration:
   discovery_url: "https://auth.company.com/.well-known/openid_configuration"
```

### Device Flow Support Issues
```bash
# Check if provider supports device flow
$ oidc-pam check-device-flow https://auth.company.com

❌ Device authorization endpoint not found
📋 Available grant types: authorization_code, implicit, refresh_token

💡 Solution: This provider doesn't support device flow.
   Consider using authorization code flow with PKCE or a different provider.
```

### Scope and Claims Issues
```bash
# Debug claims and scopes
$ oidc-pam debug-claims alice@company.com

🔐 Authenticating to debug claims...
📱 Visit: https://company.okta.com/device
🔑 Code: DEBUG-5678

✅ Token received. Claims analysis:

📧 Email claim: ✅ alice@company.com (from 'email')
👤 Username claim: ✅ alice@company.com (from 'preferred_username')  
👥 Groups claim: ❌ Not found
   Available claims: email, preferred_username, name, sub, aud, iss, iat, exp

💡 Solution: Configure custom groups scope or modify user_mapping:
   scopes: ["openid", "email", "profile", "groups"]
   user_mapping:
     groups_claim: "custom:groups"  # Use your provider's groups claim
```

## Security Considerations

### Client Registration Security
```yaml
# Secure client configuration practices
oidc:
  providers:
    - name: "production-provider"
      issuer: "https://auth.company.com"
      client_id: "prod-ssh-client"
      
      # Security settings
      security:
        require_pkce: true                    # Require PKCE for security
        verify_audience: true                 # Verify JWT audience
        require_auth_time: true               # Require recent authentication
        max_token_age: 3600                   # Maximum token age (1 hour)
        clock_skew_tolerance: 300             # 5 minutes clock skew
        
        # Certificate pinning for high security environments
        tls_verification:
          pin_certificates: true
          trusted_ca_bundle: "/etc/ssl/certs/company-ca.pem"
          
        # Rate limiting to prevent abuse
        rate_limiting:
          max_requests_per_minute: 60
          max_concurrent_auths: 10
```

### Audit and Compliance
```yaml
audit:
  # Comprehensive logging for compliance
  events:
    - provider_discovery
    - authentication_attempts
    - token_validation
    - authorization_decisions
    - configuration_changes
    
  # Structured logging format
  format: "json"
  
  # Integration with SIEM systems
  outputs:
    - type: "syslog"
      facility: "auth"
      severity: "info"
    - type: "file"
      path: "/var/log/oidc-auth/audit.log"
      rotation: "daily"
    - type: "http"
      url: "https://siem.company.com/api/events"
      headers:
        Authorization: "Bearer ${SIEM_TOKEN}"
```

## Conclusion

The universal OIDC provider support in OIDC PAM demonstrates the power of building on open standards. With just **three pieces of information** (issuer URL, client ID, and desired scopes), the system can integrate with any OIDC-compliant identity provider.

### Key Benefits of Universal Support

1. **Vendor Agnostic**: No lock-in to specific identity providers
2. **Future Proof**: Works with new providers automatically
3. **Minimal Configuration**: Just issuer URL and client ID required
4. **Standard Protocols**: Leverages OIDC Discovery and Device Flow
5. **Enterprise Ready**: Supports multi-provider, complex policies
6. **Cloud Native**: Integrates with cloud secret management
7. **Simple Deployment**: One-line installation for any provider

### Configuration Complexity: **Minimal**

Regardless of whether you're using Okta, Azure AD, Auth0, Google Workspace, Keycloak, or a custom OIDC provider, the configuration pattern is identical and remarkably simple. The complexity of OIDC discovery, endpoint management, and protocol handling is abstracted away, leaving administrators with a clean, provider-agnostic configuration interface.

This universal approach means organizations can:
- **Switch providers** without reconfiguring hosts
- **Support multiple providers** simultaneously  
- **Leverage existing identity infrastructure** regardless of vendor
- **Deploy consistently** across hybrid and multi-cloud environments
- **Future-proof** their authentication architecture

The beauty of standards-based design is that it **just works** - everywhere, with everything, all the time. 🎯