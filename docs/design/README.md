# Design notes

Pre-implementation design and positioning documents, written before or alongside
the initial build and kept for provenance. They sat in the repository root, where
they outnumbered the actual documentation and read as if they described the
shipped system.

**They do not describe the current system, and they are not maintained.** They
describe intended and in some cases purely aspirational behaviour: features that
were never built, features that were built differently, and — in two cases —
integrations with entirely separate projects. Treat every capability claim in
here as a proposal, not as documentation.

For what the software actually does, read, in this order:

| Document | Covers |
|---|---|
| [`README.md`](../../README.md) | What the project is, and its current status |
| [`QUICK-START.md`](../../QUICK-START.md) | Getting a broker and a PAM stack running |
| [`DEPLOYMENT.md`](../../DEPLOYMENT.md) | Production install, operations, `oidc-admin` |
| [`configs/CONFIGURATION-GUIDE.md`](../../configs/CONFIGURATION-GUIDE.md) | Provider setup, multi-provider precedence |
| [`configs/pam/README.md`](../../configs/pam/README.md) | PAM stack semantics and module arguments |
| [`SECURITY.md`](../../SECURITY.md) | Threat model, reporting, supported versions |
| [`CHANGELOG.md`](../../CHANGELOG.md) | What actually changed, and when |

## Contents

| File | What it is |
|---|---|
| [`oidc_pam_project.md`](oidc_pam_project.md) | The original project sketch: architecture diagram, proposed layout, intended MFA support |
| [`oidc_pam_comprehensive.md`](oidc_pam_comprehensive.md) | Enterprise positioning and a broad feature narrative |
| [`oidc_provider_configuration.md`](oidc_provider_configuration.md) | Early provider-configuration survey. Superseded by `configs/CONFIGURATION-GUIDE.md` and the templates in `configs/providers/`; the YAML here does not all match the current schema |
| [`research_computing_oidc.md`](research_computing_oidc.md) | Research-computing scenarios (Globus Auth, institutional identity, allocations) |
| [`tailscale_oidc_integration.md`](tailscale_oidc_integration.md) | Proposed zero-trust access design combining this project with Tailscale |
| [`cloudworkstation_oidc_integration.md`](cloudworkstation_oidc_integration.md) | Integration case for the separate CloudWorkstation project, including market and ROI argument |

The last two are about adjacent projects rather than this one.
