# Schema Explanation

## Entity Relationship Summary

### Core Entities

#### Users
Represents a system user. Mapped from dataset features:
- `auth_mechanism` ← Authentication_Mechanisms (MFA, SSO, Password, Biometric)
- `identity_verified` ← User_Identity_Management
- `geolocation` ← Geolocation_Restrictions
- `cloud_provider` ← Cloud_Service_Provider
- `account_locked` ← Account_Lockout_Policies
- `failed_login_count` ← Account_Lockout_Policies

#### Roles
Named collections of permissions. Mapped from:
- `auth_model` ← Authorization_Models (RBAC, ABAC, PBAC)
- `is_privileged` ← Privileged_Access_Management
- Role names ← User_Roles (Admin, SuperAdmin, User, Guest)

#### Permissions
Granular access rights. Mapped from:
- `access_level` ← Access_Levels (Read, Write, Modify, Admin)
- `data_sensitivity` ← Data_Sensitivity_Classification
- `requires_mfa` ← Authentication_Mechanisms + Privileged_Access_Management
- `time_restricted` ← Time_Based_Access
- `geo_restricted` ← Geolocation_Restrictions
- `api_permission` ← API_Access_Control
- `compliance_tag` ← Compliance_Requirements (GDPR, HIPAA, SOX)

#### Policies
Security rule sets applied to roles. Mapped from:
- `zero_trust` ← Zero_Trust_Architecture
- `least_privilege` ← Least_Privilege_Principle
- `dlp_enabled` ← DLP_Policies
- `mfa_required` ← Authentication_Mechanisms
- `geo_restriction` ← Geolocation_Restrictions
- `time_window_*` ← Time_Based_Access
- `compliance_tag` ← Compliance_Requirements
- `security_score` ← Security_Score (1–5 from dataset)

### Junction Tables

| Junction      | Connects           | Additional Attributes                     |
|---------------|--------------------|-------------------------------------------|
| UserRole      | Users ↔ Roles      | assigned_by, assigned_at, expires_at      |
| RolePermission| Roles ↔ Permissions| granted_by, granted_at                    |
| RoleHierarchy | Roles ↔ Roles      | parent_role, child_role (self-referential)|
| PolicyRole    | Policies ↔ Roles   | —                                         |

### Supporting Tables

- **Sessions**: Active/expired sessions; maps to User_Session_Management, Token_based_Access_Control
- **AuditLogs**: All DDL/DML changes; maps to Audit_Trails, Logging_and_Monitoring
- **PrivilegeRequests**: Escalation workflow; maps to Privileged_Access_Management, Dynamic_Access_Management

## Normalization Notes

- All tables are in **BCNF**
- No partial dependencies (all non-key attributes depend on the full PK)
- No transitive dependencies
- Multi-valued facts stored in separate junction tables (UserRole, RolePermission, PolicyRole)
- ENUM types used for constrained string domains to enforce valid values at DB level

## 50-Factor Mapping Summary

| Dataset Factor                         | Schema Location                                      |
|----------------------------------------|------------------------------------------------------|
| Authentication Mechanisms              | Users.auth_mechanism, Sessions.auth_mechanism        |
| Authorization Models                   | Roles.auth_model, Policies.auth_model                |
| User Identity Management               | Users.identity_verified                              |
| Access Levels                          | Permissions.access_level                             |
| User Roles                             | Roles table                                          |
| Security Policies                      | Policies table                                       |
| Compliance Requirements                | Permissions.compliance_tag, Policies.compliance_tag  |
| User Session Management                | Sessions table                                       |
| Privileged Access Management           | Roles.is_privileged, PrivilegeRequests               |
| Third-Party Integrations               | Policies.description (noted), Identity Federation    |
| Cloud Service Provider                 | Users.cloud_provider, Sessions.cloud_provider        |
| Geolocation Restrictions               | Users.geolocation, Permissions.geo_restricted        |
| Time-Based Access                      | Permissions.time_restricted, Policies.time_window_*  |
| User Behavior Analytics                | AuditLogs (behavioral pattern source)                |
| Network Security Controls              | Permissions on vpc-network resource                  |
| Access Control Lists                   | RolePermission table (ACL model)                     |
| Encryption Policies                    | Permissions.data_sensitivity                         |
| Data Sensitivity Classification        | Permissions.data_sensitivity (ENUM)                  |
| Logging and Monitoring                 | AuditLogs table                                      |
| Security Groups                        | Roles (grouped permissions = security groups)        |
| Identity Federation                    | Policies (Identity Federation Policy)                |
| Least Privilege Principle              | Policies.least_privilege                             |
| Access Control Propagation             | RoleHierarchy table                                  |
| API Access Control                     | Permissions.api_permission                           |
| Cloud Workload Identity                | Users (bot/service accounts)                         |
| Audit Trails                           | AuditLogs table                                      |
| Access Revocation                      | UserRole.is_active (soft revocation)                 |
| Cross-Region Access                    | Policies (Cross-Region Replication Policy)           |
| DLP Policies                           | Policies.dlp_enabled                                 |
| Multi-Tenancy Security                 | Policies (Multi-Tenant Isolation)                    |
| Cloud Orchestration Layer Security     | Policies (Kubernetes Access Policy)                  |
| Token-based Access Control             | Sessions.session_token, Policies (Token Rotation)    |
| Access Control for Serverless          | Permissions on serverless-functions resource         |
| Granular Access Control                | Permissions table (fine-grained)                     |
| Cloud Native Directory Services        | Users (identity management)                          |
| Access to Logs and Monitoring Tools    | Permissions (logs.read, logs.admin)                  |
| Custom Access Control Policies         | Policies table                                       |
| Zero Trust Architecture                | Policies.zero_trust                                  |
| Infrastructure as Code                 | Policies (Infrastructure as Code Policy)             |
| VPC Controls                           | Policies (VPC Segmentation Policy)                   |
| Segmentation of Duties                 | Q23 query, Policies (SOX)                            |
| Instance Metadata Service Access       | Policies (Instance Metadata Policy)                  |
| Shared Responsibility Model            | Policies (Shared Responsibility Model)               |
| Cloud Storage Access Policies          | Permissions on cloud-storage resource                |
| Data Governance Framework              | Policies (Data Governance Framework)                 |
| API Gateway Security                   | Permissions.api_permission, APIGatewayAdmin role     |
| Dynamic Access Management              | Policies (Dynamic Risk Access Policy)                |
| Account Lockout Policies               | Users.account_locked, Trigger T5                     |
| Access to Sensitive Compute Resources  | Permissions on compute-instances, database           |
| Penetration Testing                    | Policies, PenTester role, pentest.execute permission |
