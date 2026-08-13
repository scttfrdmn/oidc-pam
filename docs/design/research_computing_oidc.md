# OIDC PAM for Research Computing: Globus Auth & Academic Integration

## Executive Summary

The research computing community has unique authentication challenges: multi-institutional collaborations, federated identity management, grant compliance requirements, and complex resource sharing agreements. OIDC PAM with Globus Auth integration provides a modern, secure, and collaborative solution that addresses these specific needs while maintaining the familiar SSH workflow researchers depend on.

## The Research Computing Authentication Challenge

### Current State: Fragmented and Inefficient
```
Traditional Research Computing Access (Broken)
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Local Accounts │    │   SSH Keys      │    │ Manual Sharing  │
│ Per Institution │───▶│ Proliferation   │───▶│ Collaboration   │
│ Manual Process  │    │ No Lifecycle    │    │ Security Gaps   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        ❌                        ❌                        ❌
   Account Sprawl           Key Management          Poor Collaboration
   Weeks to provision       No audit trail         Manual processes
   No federation           Security risks          Compliance issues
```

### Vision: Federated, Secure, Collaborative
```
Modern Research Computing Access (Revolutionary)
┌─────────────────────────────────────────────────────────────────┐
│                    Federated Identity Layer                     │
│     Globus Auth + Institutional SSO + Google Workspace         │
└─────────────────────────────────────────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                │               │               │
                ▼               ▼               ▼
┌─────────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  Research Identity  │ │ Modern SSH Auth │ │  Collaboration  │
│                     │ │                 │ │    & Sharing    │
│ • Globus Federation │ │ • OIDC PAM      │ │ • Project-based │
│ • Institutional SSO │ │ • Passkey Auth  │ │ • Temporary     │
│ • Cross-site Access │ │ • Auto SSH Keys │ │ • Audit Trails  │
│ • Grant Compliance  │ │ • Mobile-first  │ │ • Policy Engine │
└─────────────────────┘ └─────────────────┘ └─────────────────┘
```

## Globus Auth Integration

### Why Globus Auth is Perfect for Research Computing

**Federated Identity**: Globus Auth already federates with 100+ research institutions
**Research-Focused**: Purpose-built for scientific collaboration and data sharing
**Institutional Trust**: Trusted by NSF, NIH, DOE, and major research institutions
**Cross-Institutional**: Seamless collaboration across institutional boundaries
**Grant Compliance**: Built-in audit trails and access controls for funded research

### Globus Auth Configuration
```yaml
# /etc/oidc-auth/broker.yaml - Research Computing Configuration
oidc:
  providers:
    - name: "globus-research"
      issuer: "https://auth.globus.org"
      client_id: "12345678-abcd-1234-efgh-123456789012"
      scopes: [
        "openid",
        "email", 
        "profile",
        "urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships",
        "urn:globus:auth:scope:nexus.api.globus.org:groups"
      ]
      
      # Research-specific user mapping
      user_mapping:
        username_claim: "preferred_username"
        email_claim: "email"
        name_claim: "name"
        groups_claim: "groups"
        organization_claim: "organization"
        institution_claim: "institution"
        orcid_claim: "orcid"
        
      # Research computing policies
      research_policies:
        enable_project_groups: true
        enable_institutional_validation: true
        enable_allocation_checking: true
        enable_data_use_agreements: true

# Research-specific authentication policies
authentication:
  research_computing:
    # High-Performance Computing clusters
    hpc_access:
      require_groups: ["hpc-users", "active-researchers"]
      require_institutional_affiliation: true
      require_allocation_verification: true
      max_session_duration: "24h"
      auto_walltime_management: true
      
    # Sensitive research data repositories
    sensitive_data:
      require_groups: ["data-approved", "pi-sponsored"]
      require_irb_approval: true
      require_data_use_agreement: true
      max_session_duration: "8h"
      require_reason_logging: true
      
    # Collaborative research environments
    collaboration:
      allow_cross_institutional: true
      require_project_membership: true
      enable_temporary_access: true
      max_collaborator_session: "12h"
      
    # Open science resources
    open_science:
      allow_public_access: true
      rate_limiting: true
      max_session_duration: "4h"
      require_publication_citation: true
```

### Globus Auth Setup Process

#### 1. Globus Developer Registration
```bash
# Register your application at Globus Developers Console
# URL: https://developers.globus.org

# Application Configuration:
Application Name: "University HPC SSH Access"
Application Type: "Native Client" 
Grant Types: ["authorization_code", "device_code"]
Redirect URIs: ["http://localhost:8080/callback"]
Scopes: [
  "openid",
  "email", 
  "profile",
  "urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships"
]
```

#### 2. Institutional Federation Setup
```yaml
# Configure institutional identity federation
globus_federation:
  institution: "University of Research"
  domain: "research.edu"
  
  # Link to institutional SSO
  identity_providers:
    - name: "University SSO"
      entity_id: "https://sso.research.edu"
      type: "saml"
      
    - name: "InCommon Federation"
      entity_id: "https://incommon.org"
      type: "federation"
      
  # Group management integration
  group_sources:
    - type: "globus_groups"
      sync_interval: "1h"
    - type: "institutional_ldap"
      ldap_url: "ldap://directory.research.edu"
      base_dn: "ou=people,dc=research,dc=edu"
```

#### 3. Research Project Group Configuration
```yaml
# Define research project groups in Globus
research_projects:
  - name: "NSF Climate Change Study"
    globus_group_uuid: "550e8400-e29b-41d4-a716-446655440001"
    members:
      - "alice@university.edu"
      - "bob@collaborator-university.edu"
      - "carol@international-institute.org"
    resources:
      - "climate-hpc-cluster"
      - "weather-data-repository"
    
  - name: "NIH Genomics Pipeline"
    globus_group_uuid: "550e8400-e29b-41d4-a716-446655440002"
    data_classification: "controlled"
    irb_approval_required: true
    members:
      - "genomics-team@med-school.edu"
    resources:
      - "secure-genomics-cluster"
      - "hipaa-compliant-storage"
```

## Google Workspace for Educational Institutions

### Configuration for University Google Workspace
```yaml
oidc:
  providers:
    - name: "university-google"
      issuer: "https://accounts.google.com"
      client_id: "123456789-university.apps.googleusercontent.com"
      scopes: [
        "openid",
        "email",
        "profile", 
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
        "https://www.googleapis.com/auth/admin.directory.user.readonly"
      ]
      
      # University-specific configuration
      hosted_domain: "university.edu"  # Restrict to university domain
      
      user_mapping:
        username_claim: "email"
        groups_claim: "groups"
        department_claim: "department"
        student_id_claim: "student_id"
        faculty_status_claim: "faculty_status"
        
      # Academic policies
      academic_policies:
        verify_enrollment_status: true
        check_academic_standing: true
        enable_course_groups: true
        semester_based_access: true
```

### Google Workspace Setup for Universities
```bash
# Google Workspace Admin Console Configuration

# 1. Create OAuth 2.0 Client
# - Application Type: Desktop Application
# - Authorized Redirect URIs: http://localhost:8080/callback

# 2. Enable Required APIs
# - Admin SDK API
# - Directory API  
# - Groups API

# 3. Configure OAuth Consent Screen
# - User Type: Internal (university domain only)
# - Application Name: "University Computing Access"
# - Authorized Domains: university.edu

# 4. Set up organizational units and groups
# - Faculty group: faculty@university.edu
# - Graduate students: grad-students@university.edu
# - Undergraduate students: undergrad@university.edu
# - Research groups: research-{project-name}@university.edu
```

## Multi-Provider Research Environment

### Complete Research Computing Configuration
```yaml
# /etc/oidc-auth/broker.yaml - Multi-provider research setup
oidc:
  providers:
    # Primary: Globus Auth for research identity
    - name: "globus-primary"
      issuer: "https://auth.globus.org"
      client_id: "globus-research-client"
      scopes: ["openid", "email", "profile", "groups"]
      priority: 1
      user_type: "researcher"
      enable_cross_institutional: true
      
    # Secondary: University Google Workspace
    - name: "university-google"
      issuer: "https://accounts.google.com"
      client_id: "university-google-client"
      scopes: ["openid", "email", "profile", "groups"]
      hosted_domain: "university.edu"
      priority: 2
      user_type: "local_student"
      
    # Tertiary: Direct institutional SSO
    - name: "university-sso"
      issuer: "https://sso.university.edu"
      client_id: "local-sso-client"
      scopes: ["openid", "email", "eduPersonAffiliation", "memberOf"]
      priority: 3
      user_type: "institutional"
      
    # Research partner institutions
    - name: "partner-institutions"
      issuer: "https://federation.research-alliance.org"
      client_id: "alliance-ssh-client"
      scopes: ["openid", "email", "profile", "institution", "projects"]
      priority: 4
      user_type: "external_researcher"
      
    # ORCID for publication/identity verification
    - name: "orcid-verification"
      issuer: "https://orcid.org"
      client_id: "orcid-ssh-client"
      scopes: ["openid"]
      priority: 5
      user_type: "identity_verification"
      verification_only: true

# Research computing access policies
authentication:
  research_policies:
    # Faculty and research staff access
    faculty_hpc:
      allowed_providers: ["globus-primary", "university-sso"]
      require_groups: ["faculty", "research-staff", "pi-approved"]
      max_session_duration: "48h"
      enable_job_submission: true
      enable_data_transfer: true
      
    # Graduate student research access  
    graduate_research:
      allowed_providers: ["globus-primary", "university-google", "university-sso"]
      require_groups: ["graduate-students", "research-approved"]
      require_advisor_approval: true
      max_session_duration: "24h"
      enable_supervised_access: true
      
    # Undergraduate course access
    undergraduate_courses:
      allowed_providers: ["university-google", "university-sso"]
      require_groups: ["undergraduates", "course-enrolled"]
      max_session_duration: "4h"
      enable_sandbox_only: true
      auto_cleanup_files: true
      
    # Cross-institutional collaboration
    external_collaborators:
      allowed_providers: ["globus-primary", "partner-institutions"]
      require_groups: ["external-researchers", "collaboration-approved"]
      require_project_membership: true
      require_pi_sponsorship: true
      max_session_duration: "12h"
      audit_level: "detailed"
      
    # Sensitive data analysis
    controlled_data_access:
      allowed_providers: ["globus-primary"]
      require_groups: ["data-stewards", "irb-approved"]
      require_training_certification: true
      require_data_use_agreement: true
      max_session_duration: "8h"
      no_data_export: true
      audit_level: "maximum"

# Research-specific time and access controls
  time_based_policies:
    # Course access during semester
    academic_calendar:
      fall_semester: "2024-08-26 to 2024-12-20"
      spring_semester: "2025-01-15 to 2025-05-15"
      summer_session: "2025-05-20 to 2025-08-15"
      
    # Research access (year-round with maintenance windows)
    research_schedule:
      maintenance_windows:
        - "Sunday 02:00-06:00 UTC"
        - "First Monday of month 01:00-05:00 UTC"
      holiday_restrictions:
        - "2024-12-23 to 2025-01-02"  # Winter break
```

## Research Workflow Examples

### Multi-Institutional Climate Research
```bash
# Dr. Alice (University of Colorado) accessing NCAR supercomputer
$ ssh alice@cheyenne.ucar.edu

🔐 Research Computing Authentication Required
📊 Resource: NCAR Cheyenne Supercomputer
🎓 Authentication via Globus Research Identity

📱 Visit: https://auth.globus.org/device
🔑 Code: CLMT-5432

# On researcher's phone:
# 1. "NCAR HPC Access Request"
# 2. Globus authenticates with University of Colorado SSO
# 3. "Grant SSH access to Cheyenne for Climate Study project?" → Approve
# 4. Cross-institutional access validated
# 5. Project membership confirmed: "NSF Climate Change Impact Study"

✅ Authentication successful!
🎓 Institution: University of Colorado Boulder  
👤 Researcher: Dr. Alice Johnson (ORCID: 0000-0001-2345-6789)
📝 Project: NSF Award #12345 - Climate Change Impact Study
⏰ Session Duration: 24 hours (project policy)
💾 Data Access: Climate models, observational data
🤝 Collaborators: 12 researchers across 8 institutions

alice@cheyenne:~$ module load ncar-pylib
alice@cheyenne:~$ qsub climate_analysis.pbs
```

### Genomics Data Analysis Workflow
```bash
# Graduate student accessing secure genomics cluster
$ ssh student@secure-genomics.university.edu

🔐 Controlled Data Access - Enhanced Security Required
🧬 Resource: Secure Genomics Computing Cluster  
📋 Data Classification: Controlled/IRB Required

📱 Authenticate via University Google Workspace
🔗 Visit: https://accounts.google.com/device
🔑 Code: GNMX-7890

# After Google Workspace authentication:
✅ Student: Sarah Chen (student.id: 12345678)
✅ Department: Computational Biology
✅ Advisor: Dr. Robert Smith (PI approval verified)
✅ IRB Training: Completed 2024-01-15 (Valid)
✅ Data Use Agreement: Signed 2024-02-01
✅ Project: "Cancer Genomics Analysis Pipeline"

⚠️  Controlled Data Environment Active
   - No data export permitted
   - All activities logged for compliance
   - Session limited to 8 hours
   - Auto-logout at 18:00 (lab policy)

sarah@genomics-cluster:~$ module load samtools/1.17
sarah@genomics-cluster:~$ sbatch --partition=controlled genomics_pipeline.sh
```

### Course-Based Computing Access
```bash
# Undergraduate accessing course computing resources
$ ssh jdoe@cs-course-cluster.university.edu

🎓 Course Computing Environment
📚 Course: CS 5593 - High Performance Computing
👨‍🏫 Instructor: Prof. Michael Wilson

📱 Sign in with University Google Account
🔗 Visit: https://accounts.google.com/device  
🔑 Code: CRSE-2468

✅ Student: John Doe (john.doe@university.edu)
✅ Course: CS 5593 Fall 2024 (Enrolled)
✅ Academic Standing: Good standing
✅ Computing Quota: 50 CPU hours remaining
⏰ Session: 4 hours maximum
🧹 Auto-cleanup: Files removed after 7 days

Welcome to HPC Course Environment!
Assignment due: 2024-10-15
Remaining quota: 45 hours

jdoe@course-cluster:~$ mpirun -np 4 ./parallel_assignment
```

## Research Computing Integration Features

### Allocation and Resource Management
```yaml
# Integration with resource allocation systems
resource_management:
  allocation_systems:
    - name: "XSEDE/ACCESS"
      type: "national_allocation"
      validation_endpoint: "https://allocations.access-ci.org/api/validate"
      required_for_resources: ["stampede2", "bridges2", "expanse"]
      
    - name: "University Internal"
      type: "institutional_allocation" 
      validation_endpoint: "https://hpc.university.edu/api/allocations"
      integration_method: "slurm_accounting"
      
  quota_enforcement:
    cpu_hours: true
    storage_quota: true
    gpu_hours: true
    priority_adjustment: true

# Job submission integration
job_submission:
  schedulers:
    - type: "slurm"
      integration: "ssh_key_forwarding"
      auto_account_mapping: true
      
    - type: "pbs"
      integration: "kerberos_forwarding"
      project_code_mapping: true
      
  policies:
    max_concurrent_jobs: 10
    priority_boost_for_course: true
    resource_limits_by_group: true
```

### Data Transfer and Globus Integration
```yaml
# Seamless integration with Globus data transfer
globus_integration:
  endpoints:
    - name: "University Research Storage"
      uuid: "550e8400-e29b-41d4-a716-446655440000"
      auto_activate: true
      
    - name: "HPC Scratch Storage" 
      uuid: "550e8400-e29b-41d4-a716-446655440001"
      activation_requirements: ["ssh_login"]
      
  auto_permissions:
    # Automatically grant Globus transfer permissions based on SSH access
    enable: true
    scope_mapping:
      "hpc-users": ["read", "write"]
      "data-stewards": ["read", "write", "delete"]
      "collaborators": ["read"]
      
  data_publication:
    enable_doi_minting: true
    repository_integration: ["zenodo", "dryad", "figshare"]
    metadata_extraction: true
```

### Research Compliance and Audit
```yaml
# Research-specific compliance features
compliance:
  grant_reporting:
    nsf_reporting: true
    nih_reporting: true
    doe_reporting: true
    usage_analytics: true
    
  audit_requirements:
    data_access_logging: "detailed"
    collaboration_tracking: true
    publication_linking: true
    retention_period: "7_years"
    
  data_governance:
    classification_enforcement: true
    export_control_checking: true
    irb_compliance_validation: true
    data_use_agreement_tracking: true

# Academic calendar integration  
academic_integration:
  semester_policies:
    enable_course_based_access: true
    auto_cleanup_student_files: true
    grade_submission_integration: true
    
  research_continuity:
    summer_access_for_researchers: true
    sabbatical_access_management: true
    graduation_transition_policies: true
```

## Deployment for Research Institutions

### Multi-Campus Research University
```yaml
# Configuration for multi-campus research system
deployment:
  campuses:
    - name: "main_campus"
      location: "Boulder, CO"
      resources: ["hpc_cluster", "genomics_lab", "physics_computing"]
      primary_provider: "university-sso"
      
    - name: "medical_campus"
      location: "Aurora, CO" 
      resources: ["medical_hpc", "hipaa_storage", "clinical_research"]
      primary_provider: "medical-sso"
      compliance_level: "hipaa"
      
    - name: "marine_station"
      location: "Friday Harbor, WA"
      resources: ["field_computing", "oceanography_data"]
      primary_provider: "globus-primary"
      connectivity: "satellite"

  federation:
    cross_campus_access: true
    shared_identity_namespace: true
    unified_project_management: true
    
  high_availability:
    broker_clustering: true
    failover_sites: ["aws", "azure"]
    disaster_recovery_plan: true
```

### Research Consortium Deployment
```bash
#!/bin/bash
# Deploy OIDC PAM across research consortium

CONSORTIUM_MEMBERS=(
  "university-colorado.edu"
  "university-california.edu" 
  "mit.edu"
  "stanford.edu"
  "princeton.edu"
)

GLOBUS_CLIENT_ID="consortium-research-computing"
SHARED_CONFIG_REPO="https://github.com/research-consortium/oidc-pam-config"

for institution in "${CONSORTIUM_MEMBERS[@]}"; do
  echo "Deploying to $institution..."
  
  # Deploy with institution-specific configuration
  ssh deploy@hpc.$institution \
    "curl -sSL https://get.oidc-pam.io/install | \
     PROVIDER=globus \
     GLOBUS_CLIENT_ID=$GLOBUS_CLIENT_ID \
     INSTITUTION=$institution \
     CONFIG_REPO=$SHARED_CONFIG_REPO \
     bash"
     
  # Validate deployment
  ssh deploy@hpc.$institution "oidc-pam validate-config"
  
  echo "✅ Deployment complete for $institution"
done

echo "🎉 Research consortium deployment complete!"
echo "🔗 Federated access now available across all member institutions"
```

### Container-Based Research Computing
```dockerfile
# Research computing container with OIDC PAM
FROM ubuntu:22.04

# Install research computing software stack
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    r-base \
    julia \
    openmpi-bin \
    slurm-client \
    globus-cli

# Install OIDC PAM
RUN curl -sSL https://get.oidc-pam.io/install | \
    PROVIDER="globus" \
    GLOBUS_CLIENT_ID="${GLOBUS_CLIENT_ID}" \
    bash

# Research-specific configuration
COPY research-config.yaml /etc/oidc-auth/broker.yaml
COPY research-policies.yaml /etc/oidc-auth/policies.yaml

# Enable SSH access with OIDC PAM
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
```

```yaml
# Kubernetes deployment for research computing pods
apiVersion: apps/v1
kind: Deployment
metadata:
  name: research-computing-pods
spec:
  replicas: 10
  selector:
    matchLabels:
      app: research-computing
  template:
    metadata:
      labels:
        app: research-computing
    spec:
      containers:
        - name: research-environment
          image: research-computing/oidc-pam:latest
          env:
            - name: GLOBUS_CLIENT_ID
              valueFrom:
                secretKeyRef:
                  name: globus-config
                  key: client-id
            - name: RESEARCH_PROJECT
              valueFrom:
                fieldRef:
                  fieldPath: metadata.labels['research.project']
          ports:
            - containerPort: 22
          volumeMounts:
            - name: research-data
              mountPath: /data
            - name: user-home
              mountPath: /home
      volumes:
        - name: research-data
          persistentVolumeClaim:
            claimName: research-data-pvc
        - name: user-home
          persistentVolumeClaim:
            claimName: user-home-pvc
```

## Benefits for Research Computing Community

### For Research Institutions
- **Reduced IT overhead**: No manual account provisioning across systems
- **Enhanced security**: Modern authentication replaces shared/static credentials
- **Improved compliance**: Automated audit trails for grant and regulatory requirements
- **Cost savings**: Eliminate separate identity systems for each resource
- **Better collaboration**: Seamless cross-institutional access

### For Researchers
- **Single identity**: One login for all research computing resources
- **Mobile authentication**: Access systems securely from anywhere with passkeys
- **Simplified collaboration**: Easy temporary access for research partners
- **Faster onboarding**: Minutes instead of weeks to get computing access
- **Transparent workflow**: Familiar SSH tools with enhanced security

### For Research Computing Centers
- **Streamlined operations**: Automated user lifecycle management
- **Enhanced security posture**: Modern authentication and audit trails
- **Simplified compliance**: Built-in reporting for NSF, NIH, DOE requirements
- **Better resource utilization**: Fine-grained access control and monitoring
- **Future-proof architecture**: Standards-based approach scales with growth

### For Multi-Institutional Projects
- **Federated access**: Researchers use home institution credentials everywhere
- **Project-based permissions**: Automatic access control based on research groups
- **Compliance alignment**: Consistent audit trails across all participating sites
- **Reduced administrative burden**: Centralized identity and access management
- **Enhanced collaboration**: Secure, seamless resource sharing

## Research Computing Roadmap

### Phase 1: Core Research Integration (Q1 2025)
- [ ] Globus Auth integration and federation
- [ ] Google Workspace for educational institutions
- [ ] Basic multi-institutional access patterns
- [ ] Research project group management
- [ ] HPC scheduler integration (Slurm, PBS)

### Phase 2: Advanced Research Features (Q2 2025)
- [ ] Allocation system integration (XSEDE/ACCESS)
- [ ] Data classification and governance
- [ ] IRB and compliance automation
- [ ] ORCID identity verification
- [ ] Publication and dataset linking

### Phase 3: Ecosystem Integration (Q3 2025)
- [ ] Globus data transfer automation
- [ ] Research data repository integration
- [ ] Grant reporting and analytics
- [ ] Academic calendar and course integration
- [ ] Research computing marketplace support

### Phase 4: Advanced Collaboration (Q4 2025)
- [ ] International research collaboration
- [ ] Cloud research computing integration
- [ ] AI/ML workflow optimization
- [ ] Research reproducibility features
- [ ] Next-generation research tools

## Conclusion

The combination of OIDC PAM with Globus Auth creates a transformative solution for research computing authentication. By leveraging the federated identity infrastructure that the research community already trusts and uses, while adding modern authentication methods like passkeys, we can solve the long-standing problems of account proliferation, poor collaboration tools, and compliance challenges.

This approach respects the unique culture and requirements of research computing while bringing it into the modern era of security and user experience. Researchers get the seamless, mobile-friendly authentication they expect, while institutions get the security, compliance, and operational efficiency they need.

**The future of research computing authentication is federated, secure, and collaborative.** 🚀

---

*For research computing centers interested in pilot deployments or to contribute to the development of research-specific features, contact the OIDC PAM research computing working group.*