# OIDC PAM Configuration Guide

This guide provides comprehensive instructions for configuring the OIDC PAM authentication system for different environments and providers.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Configuration Templates](#configuration-templates)
3. [Provider-Specific Setup](#provider-specific-setup)
4. [Multiple Providers and `priority`](#multiple-providers-and-priority)
5. [Security Best Practices](#security-best-practices)
6. [Environment-Specific Configurations](#environment-specific-configurations)
7. [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Choose Your Configuration Template

Select the appropriate template based on your environment:

- **`broker-minimal.yaml`** - Simple production setup with security defaults
- **`broker-enterprise.yaml`** - Enterprise setup with advanced features

Both are loaded, validated and audit-checked by `TestShippedConfigsLoad` on every
build, so a template that cannot start the broker cannot ship (#170).

### 2. Configure Your OIDC Provider

Choose your provider and follow the specific setup guide:

- **Keycloak** - See `providers/keycloak.yaml`
- **Azure AD** - See `providers/azure-ad.yaml`
- **Okta** - See `providers/okta.yaml`
- **AWS IAM Identity Center** - See `providers/aws-identity-center.yaml`

### 3. Basic Setup Steps

1. **Install the system:**
   ```bash
   sudo ./install.sh
   ```

2. **Copy and edit configuration:**
   ```bash
   sudo cp configs/production/broker-minimal.yaml /etc/oidc-auth/broker.yaml
   sudo nano /etc/oidc-auth/broker.yaml
   ```

3. **Generate encryption key** (base64-encoded 32-byte / AES-256 key):
   ```bash
   oidc-admin gen-key        # or: openssl rand -base64 32
   ```
   The value is used directly as the AES-256 key — it must be a base64 32-byte
   key, not a passphrase. A wrong-length or non-base64 value is rejected at
   startup.

4. **Update configuration with your settings:**
   - OIDC provider URL
   - Client ID and secret
   - Required groups
   - Encryption key

5. **Start the service:**
   ```bash
   sudo systemctl start oidc-auth-broker
   sudo systemctl enable oidc-auth-broker
   ```

## Configuration Templates

### Minimal Production (`broker-minimal.yaml`)

**Use for:**
- Simple deployments
- Single OIDC provider
- Basic security requirements
- Small to medium organizations

**Features:**
- Essential security settings
- Basic audit logging
- Single provider configuration
- Minimal dependencies

**Configuration Required:**
```yaml
oidc:
  providers:
    - name: "primary"
      issuer: "https://your-oidc-provider.com"
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      scopes: ["openid", "email", "profile", "groups"]

security:
  # base64-encoded 32-byte key from `oidc-admin gen-key`
  token_encryption_key: "REPLACE-with-output-of-oidc-admin-gen-key"

authentication:
  require_groups: ["linux-users"]
```

### Enterprise Production (`broker-enterprise.yaml`)

**Use for:**
- Large organizations
- Multiple OIDC providers
- Advanced security requirements
- Compliance needs (SOC2, HIPAA, PCI-DSS)

**Features:**
- Multiple provider support
- Advanced policy engine
- Comprehensive audit logging
- Risk-based authentication
- Time-based access controls
- Network security requirements

**Key Sections:**
- Multiple OIDC providers (primary, backup, service accounts)
- Environment-specific policies (production, staging, development)
- Advanced security settings
- Comprehensive audit configuration

### Keeping Secrets Out of the File

Any `client_secret`, and `security.token_encryption_key`, may be written as a
reference instead of a literal:

```yaml
oidc:
  providers:
    - name: "primary"
      client_secret: "env:OIDC_CLIENT_SECRET"      # from the process environment
security:
  token_encryption_key: "file:/etc/oidc-auth/key"  # from a file, whitespace-trimmed
```

`env:` reads the named variable — put it in the unit's `EnvironmentFile`, which is
how a container or a secrets agent injects it — and `file:` reads a file your
secrets manager writes. A missing variable or unreadable file is a startup error,
not an empty secret.

There was a third template, `broker-cloud.yaml`, offering `${VAR:-default}` shell
interpolation and a `cloud:` section for AWS Parameter Store, Azure Key Vault and
GCP Secret Manager. Both were fiction: nothing expanded `${VAR}`, so the file
could not be parsed at all, and no field of the configuration read `cloud:`. The
file and the section were deleted in #170 — use the two prefixes above.

## Provider-Specific Setup

### Keycloak Setup

1. **Create Realm:**
   - Admin Console → Add realm
   - Name: `company`

2. **Create Client:**
   - Client ID: `oidc-pam-client`
   - Access Type: `confidential`
   - Enable: Standard Flow, Direct Access Grants, Service Accounts
   - Enable: OAuth 2.0 Device Authorization Grant

3. **Configure Scopes:**
   - Add `groups` scope
   - Configure group membership mapper

4. **Create Groups:**
   - `linux-users`
   - `administrators`
   - `developers`

**Configuration:**
```yaml
oidc:
  providers:
    - name: "keycloak-primary"
      issuer: "https://keycloak.example.com/realms/company"
      client_id: "oidc-pam-client"
      client_secret: "your-client-secret"
      user_mapping:
        username_claim: "preferred_username"
        groups_claim: "groups"
```

### Azure AD Setup

1. **Register Application:**
   - Azure Portal → Azure Active Directory → App registrations
   - Name: `OIDC PAM Client`
   - Account types: `Single tenant`

2. **Configure Authentication:**
   - Enable public client flows
   - Add platform configurations

3. **Set API Permissions:**
   - Microsoft Graph: `User.Read`, `Group.Read.All`
   - Grant admin consent

4. **Configure Token:**
   - Add optional claims: email, groups
   - Configure group claims

**Configuration:**
```yaml
oidc:
  providers:
    - name: "azure-ad-primary"
      issuer: "https://login.microsoftonline.com/your-tenant-id/v2.0"
      client_id: "your-azure-app-id"
      client_secret: "your-azure-app-secret"
      scopes: ["openid", "profile", "email", "https://graph.microsoft.com/User.Read"]
```

### Okta Setup

1. **Create Application:**
   - Okta Admin Console → Applications
   - Type: `Native Application`
   - Grant types: Authorization Code, Device Authorization, Refresh Token

2. **Configure Authorization Server:**
   - Security → API → Authorization Servers
   - Use `default` or create custom

3. **Add Claims:**
   - Groups claim: `groups`
   - Custom claims as needed

4. **Create Groups:**
   - Directory → Groups
   - Create and assign users

**Configuration:**
```yaml
oidc:
  providers:
    - name: "okta-primary"
      issuer: "https://your-domain.okta.com/oauth2/default"
      client_id: "your-okta-client-id"
      client_secret: "your-okta-client-secret"
```

### AWS IAM Identity Center Setup

AWS IAM Identity Center does not expose a public `/.well-known/openid-configuration` endpoint. The standard OIDC discovery call returns `403 Forbidden`, so the broker must be configured with `skip_discovery: true` and all endpoints supplied explicitly.

1. **Register a public client:**
   ```bash
   aws sso-oidc register-client \
     --client-type public \
     --client-name oidc-pam \
     --grant-types urn:ietf:params:oauth:grant-type:device_code \
     --region us-east-2
   ```
   Note the `clientId` and `clientSecret` from the response. The secret expires after ~90 days; re-run `register-client` to rotate it.

2. **Store credentials securely** (AWS SSM example):
   ```bash
   aws ssm put-parameter --name /oidc-pam/client-id     --value "<clientId>"     --type SecureString
   aws ssm put-parameter --name /oidc-pam/client-secret --value "<clientSecret>" --type SecureString
   ```

3. **Configure the broker** — replace `us-east-2` with your IAM Identity Center region:

```yaml
oidc:
  providers:
    - name: aws-identity-center
      issuer: "https://oidc.us-east-2.amazonaws.com"

      # IAM Identity Center returns 403 on /.well-known/openid-configuration.
      # skip_discovery bypasses OIDC discovery; all endpoints must be explicit.
      skip_discovery: true
      device_endpoint:   "https://oidc.us-east-2.amazonaws.com/device_authorization"
      token_endpoint:    "https://oidc.us-east-2.amazonaws.com/token"
      userinfo_endpoint: "https://oidc.us-east-2.amazonaws.com/userInfo"
      jwks_uri:          "https://oidc.us-east-2.amazonaws.com/.well-known/jwks.json"

      client_id:     "env:OIDC_CLIENT_ID"
      client_secret: "env:OIDC_CLIENT_SECRET"
      scopes: [openid, email, profile]

      allow_missing_nonce: true  # Device flow does not include nonce in ID token
      require_pkce: false        # RFC 8628 device flow does not use PKCE

      user_mapping:
        username_claim: preferred_username
        email_claim: email
        name_claim: name

      priority: 1
      enabled_for_login: true
```

See `providers/aws-identity-center.yaml` for a ready-to-use template.

### The `skip_discovery` Option

Any provider that lacks a publicly accessible `/.well-known/openid-configuration` can use `skip_discovery`:

| Field | Required when `skip_discovery: true` | Description |
|---|---|---|
| `skip_discovery` | — | Set to `true` to bypass OIDC discovery |
| `jwks_uri` | **required** | URL of the provider's public key set |
| `token_endpoint` | **required** | OAuth2 token endpoint |
| `device_endpoint` | recommended | RFC 8628 device authorization endpoint |
| `userinfo_endpoint` | optional | OpenID Connect UserInfo endpoint |

When `skip_discovery: true` is set, the broker constructs the OIDC provider from these fields directly using `oidc.ProviderConfig` — no network call is made to the discovery endpoint at startup.

## Multiple Providers and `priority`

A login is served by exactly one provider. When more than one is configured, the
broker picks it deterministically:

1. Providers with `enabled_for_login: false` (the default) are not candidates.
2. Providers with `verification_only: true` are not candidates either — that flag
   means the provider may confirm an identity but must not be the one a login is
   issued against. Setting both it and `enabled_for_login: true` is
   contradictory, and the broker resolves it by not offering logins.
3. The remaining candidates are ordered by `priority` **ascending — 1 is the most
   preferred**, as in `broker-enterprise.yaml`, where the primary provider is
   `priority: 1` and the failover provider is `priority: 2`.
4. A provider that omits `priority` sorts *after* every provider that sets one,
   so forgetting the field cannot promote a provider over your declared primary.
   Negative values are treated the same way, as typos rather than as a way to
   mean "first".
5. Providers with equal priority are ordered by name, so the choice is the same
   on every host and across restarts.

```yaml
oidc:
  providers:
    - name: corporate-primary
      priority: 1              # chosen for every login
      enabled_for_login: true

    - name: corporate-backup
      priority: 2              # configured, but not selected while the primary is present
      enabled_for_login: true

    - name: orcid
      priority: 3
      enabled_for_login: true
      verification_only: true  # never selected for a login
```

`sudo oidc-admin status` lists the providers the broker loaded. Note that
priority is a *preference*, not health-based failover: the broker does not
currently probe providers and fall through to the next one when the preferred
provider is unreachable, so a login against an unavailable primary fails rather
than silently using the backup.

## Security Best Practices

### 1. Encryption Keys

Generate strong encryption keys:
```bash
# Generate 32-byte encryption key
openssl rand -base64 32

# Generate for cloud environments
export TOKEN_ENCRYPTION_KEY=$(openssl rand -base64 32)
```

### 2. File Permissions

Secure configuration files:
```bash
sudo chown root:root /etc/oidc-auth/broker.yaml
sudo chmod 600 /etc/oidc-auth/broker.yaml
sudo chown -R root:root /etc/oidc-auth/
sudo chmod -R 600 /etc/oidc-auth/
```

### 3. Network Security

Configure firewall rules:
```bash
# Allow only necessary ports
sudo ufw allow ssh
sudo ufw allow 443/tcp
sudo ufw enable
```

### 4. TLS Configuration

Use proper SSL/TLS certificates:
```yaml
security:
  tls_verification:
    skip_tls_verify: false
    trusted_ca_bundle: "/etc/ssl/certs/ca-certificates.crt"
    # Optional pinning: SHA-256 fingerprints (lowercase hex, colons optional)
    # that must appear in the provider's TLS chain.
    pinned_certificates:
      - "a1b2c3...your-provider-fingerprint"
```

Pinning takes **fingerprints, not a boolean**. This guide and five configuration
files used to say `pin_certificates: true`, which is not the name of any setting;
it was discarded in silence, so pinning was off everywhere it was switched on
(#170). Get a fingerprint with:

```bash
openssl s_client -connect idp.example.com:443 </dev/null 2>/dev/null |
  openssl x509 -noout -fingerprint -sha256
```

A pinned certificate that rotates refuses every connection to the provider, and
with it every login, so pin deliberately and rotate the list with the certificate.

### 5. Audit Logging

Enable comprehensive audit logging:
```yaml
audit:
  enabled: true
  format: "json"
  retention_period: "7_years"
  events:
    - "authentication_attempts"
    - "authorization_decisions"
    - "token_validation"
    - "session_management"
    - "policy_violations"
```

### 6. How Far the Provider Is Trusted

Two things about a device-flow login are checked by the broker rather than taken on
the provider's word, and both are on by default.

**An ID token is required.** The ID token is the only part of a token response the
broker can verify: the signature, the issuing `iss`, the `aud` that says the token was
minted for *this* client, the expiry, and the nonce that makes a replayed token
useless are all claims inside it. A response without one leaves the identity coming
from `/userinfo`, which is authenticated by nothing but TLS and the bearer token, so
the broker refuses it and audits `ID_TOKEN_MISSING`. Where the two sources disagree
the ID token wins; claims that only `/userinfo` returns are still used, since the
signed token says nothing about them.

Set `require_id_token: false` only for a provider that genuinely does not issue an ID
token for the device grant, understanding that its logins are then authorized by an
unsigned JSON body:

```yaml
oidc:
  providers:
    - name: legacy-idp
      issuer: "https://idp.example.com"
      client_id: "oidc-pam"
      scopes: ["openid", "email", "profile"]
      # Accepts an identity asserted only by /userinfo: no signature, audience,
      # expiry or replay check is then possible. Check the scopes first — a missing
      # `openid` scope is the usual reason a provider returns no id_token.
      require_id_token: false
      enabled_for_login: true
```

**Every endpoint must be HTTPS.** The token, userinfo and device authorization
endpoints all come out of the provider's `/.well-known/openid-configuration` (or, under
`skip_discovery`, out of this file), and each of them receives either the device code
or an access token. The broker refuses at startup to use one that names `http://`,
because a plaintext connection silently bypasses `trusted_ca_bundle` and the
certificate pins — those only apply to a connection that negotiates TLS. Loopback
(`localhost`, `127.0.0.1`, `::1`) is the sole exception, for local development.

The host is not required to match the issuer: a token endpoint on a different host is
ordinary — Google's issuer is `accounts.google.com` and its token endpoint is on
`oauth2.googleapis.com`. Only the scheme is enforced.

## Binding an OIDC Identity to a Local Account

`user_mapping.username_claim` names the claim whose value must equal the local
account being logged into. By default the comparison is against the **whole**
value, case-insensitively.

When that claim is an email address or a UPN — `email` anywhere, and
`preferred_username` on Entra ID — the whole value never equals a Unix account
name, so nothing matches until you say what should happen:

```yaml
user_mapping:
  username_claim: "email"
  username_claim_strip_domain: true
  allowed_email_domains: ["example.com", "eng.example.com"]
```

That permits `alice@example.com` to log in as `alice`, and refuses
`alice@partner.example` and `root@anything`. Both keys are required together;
enabling the first without the second is a startup error.

Domains are matched exactly — no wildcards. A wildcard would re-open what the
pin exists to close: a subdomain under which an attacker can get a verified
address. Every domain you list is a domain whose local parts choose local
accounts on this host, so list only domains whose addresses you control.

The claim you name is the only claim consulted. If the token does not carry it,
the login is refused and audited as `USERNAME_CLAIM_MISSING` naming the claim —
there is no fallback to `sub` or to any other claim, because an identifier you
did not choose is not one you have audited. If your provider puts the login name
in `sub`, say so with `username_claim: "sub"`.

### Privileged accounts

No OIDC identity may log in as uid 0, or as any account with uid below 1000,
regardless of what the token says or how the mapping is configured. This holds
even for an exact claim match, because whether `root` is a legitimate destination
for a federated login does not depend on the mapping being right.

To make a deliberate exception:

```yaml
authentication:
  allow_privileged_accounts: ["deploy"]
```

Each exception is named individually — allowing `deploy` does not allow `root` —
and the broker logs a warning every time one is used. Refusals are audited as
`PRIVILEGED_ACCOUNT_DENIED`, distinct from the `IDENTITY_MISMATCH` recorded when
the claim itself does not match.

## Unknown Keys Are a Startup Error

Every key a configuration file may contain is a field of `config.Config`. Since
#170 the broker refuses to start on a key it does not read, and the error names
the key's full path — `'security.tls_verification' has invalid keys:
pin_certificates`.

It used to discard them silently, which is how `pin_certificates` disabled
certificate pinning in every file that set it, and how whole sections (`ssh:`,
`policy:`, `cloud:`, `logging:`) sat in the shipped templates reading as the
access-control rules of the system while doing nothing at all.

If an upgrade rejects a file you cannot edit at that moment, set
`OIDC_AUTH_ALLOW_UNKNOWN_CONFIG_KEYS=true` in the unit: the same list of keys is
logged as a warning and the broker starts. It is a way to stay logged in while
you clean the file up, not a setting to leave on — the keys still do nothing.

## Settings the Templates Do Not Show

These are read by the broker and are security-relevant, but appeared in no
configuration file and no document before #170. Defaults apply when the key is
absent.

| Key | Default | What it does |
|---|---|---|
| `server.socket_mode` | `0660` | Permission bits on the broker's Unix socket. |
| `server.socket_group` | *(unset)* | Group that owns the socket. With `0660` this is what decides who may open it at all. |
| `server.require_peer_auth` | `true` | Verify the peer's credentials over `SO_PEERCRED` and accept uid 0 only. Turning this off lets any local process talk to the broker; there is no reason to. |
| `server.metrics_addr` | *(unset)* | TCP address for the Prometheus `/metrics` endpoint, e.g. `127.0.0.1:9090`. Unset means no listener. The endpoint is unauthenticated — bind it to loopback. |
| `authentication.idle_timeout` | *(unset)* | Expire a session this long after its last use, in addition to `token_lifetime`. Unset means only `token_lifetime` applies. |
| `authentication.allow_privileged_accounts` | *(empty)* | The named exceptions to "no OIDC identity may log in as uid < 1000". See above. |
| `authentication.geoip_database_path` | *(unset)* | MaxMind GeoLite2 database for `geo_restrictions`. Without it every country code is empty, so an `allowed_countries` restriction denies everyone. |
| `authentication.location_history.*` | 90d, 10 entries, memory | Window, per-user cap and `persist_path` for the "unusual location" risk signal. |
| `security.tls_verification.pinned_certificates` | *(empty)* | SHA-256 fingerprints required in the provider's TLS chain. |
| `security.tls_verification.trusted_ca_bundle` | *(unset)* | PEM bundle that replaces the system trust store for provider connections. |
| `audit.buffer_size` | `1000` | Capacity of the in-memory audit event channel. |
| `audit.overflow_strategy` | `block` | What happens when that channel is full: `block` (backpressure), `sync` (write inline), or `drop` (discard and count). `drop` loses audit records and must be chosen deliberately. |
| `audit.outputs[].type` | — | `file`, `stdout`, `syslog` or `http`. Any other value is refused at startup. |

## Authentication Policies

An `authentication.policies` entry is selected by its **name**:

- `default` applies to **every host**. Use this unless you need per-host rules.
- Any other name is matched against the **hostname of the machine being logged
  into** — exactly, or as a domain component. A policy named `production`
  applies on `production` and on `api.production.example.com`, but not on
  `prod-login-01`.

The name is the only selector a policy has. There is no way to scope a policy to
an operation (`sudo`, `su`) or to an environment that is not part of the
hostname; a policy whose name matches no host is inert, and the broker logs a
warning naming it at startup.

Every matching policy applies. `require_groups` is the union of the global
`authentication.require_groups` and every matching policy's, and
`max_session_duration` is the smallest — so an additional matching policy can
only further restrict access.

## Environment-Specific Configurations

Deploy one configuration per environment and name its policy `default`, so that
it applies to the hosts in that environment regardless of what they are called.

### Development Environment

```yaml
authentication:
  policies:
    default:
      require_groups: ["developers"]
      max_session_duration: "8h"
      allow_untrusted_devices: true
      audit_level: "basic"

security:
  tls_verification:
    skip_tls_verify: true  # Only for development
```

### Staging Environment

```yaml
authentication:
  policies:
    default:
      require_groups: ["developers", "qa-team"]
      max_session_duration: "4h"
      require_device_trust: true
      audit_level: "standard"
```

### Production Environment

```yaml
authentication:
  policies:
    default:
      require_groups: ["production-access"]
      max_session_duration: "2h"
      require_device_trust: true
      require_additional_mfa: true
      session_recording: true
      audit_level: "detailed"
```

## Troubleshooting

### Common Issues

1. **"Invalid client credentials"**
   - Check client ID and secret
   - Verify client is enabled
   - Check client type (confidential vs public)

2. **"User not in required group"**
   - Verify group membership in OIDC provider
   - Check group claim configuration
   - Verify group mapping

3. **"Token validation failed"**
   - Check token lifetime settings
   - Verify clock synchronization
   - Check issuer URL

4. **"Device flow not supported"**
   - Enable device flow in OIDC provider
   - Check device authorization endpoint
   - Verify grant types

### Debug Configuration

Enable debug logging:
```yaml
server:
  log_level: "debug"
```

`server.log_level` is the only verbosity control; there is no per-component
logging configuration.

### Test Configuration

Test OIDC discovery:
```bash
curl https://your-provider.com/.well-known/openid-configuration
```

Test device flow:
```bash
curl -X POST https://your-provider.com/device/authorize \
  -d "client_id=your-client-id" \
  -d "scope=openid profile email groups"
```

### Log Analysis

Monitor audit logs:
```bash
sudo tail -f /var/log/oidc-auth/audit.log | jq
```

Check service status:
```bash
sudo systemctl status oidc-auth-broker
sudo journalctl -u oidc-auth-broker -f
```

## Migration Guide

### From Version 0.x to 1.x

1. **Backup current configuration:**
   ```bash
   sudo cp /etc/oidc-auth/broker.yaml /etc/oidc-auth/broker.yaml.backup
   ```

2. **Update configuration format:**
   - Review new configuration options
   - Update provider settings
   - Add new security settings

3. **Test configuration:**
   ```bash
   sudo oidc-auth-broker --config /etc/oidc-auth/broker.yaml --validate
   ```

4. **Restart service:**
   ```bash
   sudo systemctl restart oidc-auth-broker
   ```

## Support

For additional support:

- **Documentation:** [GitHub Wiki](https://github.com/scttfrdmn/oidc-pam/wiki)
- **Issues:** [GitHub Issues](https://github.com/scttfrdmn/oidc-pam/issues)
- **Discussions:** [GitHub Discussions](https://github.com/scttfrdmn/oidc-pam/discussions)

## Contributing

To contribute to the configuration templates:

1. Fork the repository
2. Create a feature branch
3. Add your configuration template
4. Update this guide
5. Submit a pull request

Templates should include:
- Complete working configuration
- Setup instructions
- Common issues and solutions
- Testing procedures