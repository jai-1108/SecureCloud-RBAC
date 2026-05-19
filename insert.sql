-- ============================================================
-- RBAC System — insert.sql
-- Derived from Cloud Access Control Dataset (100k rows)
-- ============================================================

SET app.is_seeding = 'true';

-- ─────────────────────────────────────────────
-- USERS  (35 rows, including edge cases)
-- ─────────────────────────────────────────────
INSERT INTO Users (username, email, full_name, auth_mechanism, identity_verified, geolocation, cloud_provider, is_active, account_locked, failed_login_count) VALUES
('alice.admin',    'alice@corp.com',       'Alice Admin',       'MFA',       TRUE,  'US',        'AWS',       TRUE,  FALSE, 0),
('bob.user',       'bob@corp.com',         'Bob User',          'Password',  TRUE,  'Germany',   'Azure',     TRUE,  FALSE, 0),
('carol.super',    'carol@corp.com',       'Carol SuperAdmin',  'MFA',       TRUE,  'US',        'GCP',       TRUE,  FALSE, 0),
('dave.guest',     'dave@corp.com',        'Dave Guest',        'SSO',       FALSE, 'India',     'AWS',       TRUE,  FALSE, 2),
('eve.analyst',    'eve@corp.com',         'Eve Analyst',       'Biometric', TRUE,  'UK',        'Azure',     TRUE,  FALSE, 0),
('frank.dev',      'frank@corp.com',       'Frank Developer',   'MFA',       TRUE,  'Australia', 'GCP',       TRUE,  FALSE, 0),
('grace.ops',      'grace@corp.com',       'Grace Ops',         'SSO',       TRUE,  'US',        'AWS',       TRUE,  FALSE, 0),
('hank.readonly',  'hank@corp.com',        'Hank ReadOnly',     'Password',  FALSE, 'Germany',   'IBM Cloud', TRUE,  FALSE, 1),
('iris.devops',    'iris@corp.com',        'Iris DevOps',       'MFA',       TRUE,  'US',        'AWS',       TRUE,  FALSE, 0),
('jack.auditor',   'jack@corp.com',        'Jack Auditor',      'Biometric', TRUE,  'UK',        'Azure',     TRUE,  FALSE, 0),
-- Edge: locked account
('locked.user',    'locked@corp.com',      'Locked Account',    'Password',  FALSE, 'India',     'GCP',       TRUE,  TRUE,  5),
-- Edge: inactive user
('inactive.user',  'inactive@corp.com',    'Inactive User',     'Password',  FALSE, 'US',        'AWS',       FALSE, FALSE, 0),
-- Multi-role user
('multirole.user', 'multirole@corp.com',   'Multi Role User',   'MFA',       TRUE,  'US',        'AWS',       TRUE,  FALSE, 0),
('ken.compliance', 'ken@corp.com',         'Ken Compliance',    'MFA',       TRUE,  'Germany',   'Azure',     TRUE,  FALSE, 0),
('laura.finance',  'laura@corp.com',       'Laura Finance',     'SSO',       TRUE,  'US',        'GCP',       TRUE,  FALSE, 0),
('mike.network',   'mike@corp.com',        'Mike Network',      'MFA',       TRUE,  'UK',        'AWS',       TRUE,  FALSE, 0),
('nancy.storage',  'nancy@corp.com',       'Nancy Storage',     'Biometric', TRUE,  'Australia', 'Azure',     TRUE,  FALSE, 0),
('oscar.iam',      'oscar@corp.com',       'Oscar IAM',         'MFA',       TRUE,  'US',        'GCP',       TRUE,  FALSE, 0),
('pam.sre',        'pam@corp.com',         'Pam SRE',           'SSO',       TRUE,  'US',        'IBM Cloud', TRUE,  FALSE, 0),
('quinn.db',       'quinn@corp.com',       'Quinn DBA',         'MFA',       TRUE,  'Germany',   'AWS',       TRUE,  FALSE, 0),
('rachel.api',     'rachel@corp.com',      'Rachel API Dev',    'SSO',       TRUE,  'UK',        'Azure',     TRUE,  FALSE, 0),
('sam.cloud',      'sam@corp.com',         'Sam CloudArch',     'MFA',       TRUE,  'US',        'GCP',       TRUE,  FALSE, 0),
('tina.sec',       'tina@corp.com',        'Tina Security',     'MFA',       TRUE,  'US',        'AWS',       TRUE,  FALSE, 0),
('ulric.devlead',  'ulric@corp.com',       'Ulric DevLead',     'SSO',       TRUE,  'Germany',   'Azure',     TRUE,  FALSE, 0),
('vera.ml',        'vera@corp.com',        'Vera ML Engineer',  'Biometric', TRUE,  'India',     'GCP',       TRUE,  FALSE, 0),
('will.readonly',  'will@corp.com',        'Will ReadOnly',     'Password',  FALSE, 'UK',        'IBM Cloud', TRUE,  FALSE, 3),
('xena.sysadmin',  'xena@corp.com',        'Xena SysAdmin',     'MFA',       TRUE,  'US',        'AWS',       TRUE,  FALSE, 0),
('yann.ext',       'yann@external.com',    'Yann External',     'SSO',       FALSE, 'France',    'Azure',     TRUE,  FALSE, 0),
('zoe.temp',       'zoe@corp.com',         'Zoe Temp Worker',   'Password',  FALSE, 'US',        'GCP',       TRUE,  FALSE, 0),
('adam.privileged','adam@corp.com',        'Adam Privileged',   'MFA',       TRUE,  'US',        'AWS',       TRUE,  FALSE, 0),
-- Orphan: will have no role assigned
('orphan.user1',   'orphan1@corp.com',     'Orphan User One',   'Password',  FALSE, 'US',        'AWS',       TRUE,  FALSE, 0),
('orphan.user2',   'orphan2@corp.com',     'Orphan User Two',   'SSO',       FALSE, 'Germany',   'Azure',     TRUE,  FALSE, 0),
('bot.service1',   'bot1@corp.com',        'Service Bot One',   'MFA',       TRUE,  NULL,        'AWS',       TRUE,  FALSE, 0),
('bot.service2',   'bot2@corp.com',        'Service Bot Two',   'MFA',       TRUE,  NULL,        'GCP',       TRUE,  FALSE, 0),
('test.user',      'test@corp.com',        'Test User',         'Password',  FALSE, 'US',        'AWS',       FALSE, FALSE, 0);

-- ─────────────────────────────────────────────
-- ROLES  (30 rows, including orphan & redundant)
-- ─────────────────────────────────────────────
INSERT INTO Roles (role_name, description, auth_model, is_privileged, is_active) VALUES
('SuperAdmin',         'Full system access',                         'RBAC', TRUE,  TRUE),
('Admin',              'Administrative access',                      'RBAC', TRUE,  TRUE),
('Developer',          'Code and deploy access',                     'RBAC', FALSE, TRUE),
('Analyst',            'Read and analyse data',                      'ABAC', FALSE, TRUE),
('Guest',              'Minimal read-only access',                   'RBAC', FALSE, TRUE),
('Auditor',            'Read audit logs and reports',                'RBAC', FALSE, TRUE),
('NetworkAdmin',       'Manage network resources',                   'RBAC', TRUE,  TRUE),
('StorageAdmin',       'Manage cloud storage',                       'RBAC', TRUE,  TRUE),
('IAMAdmin',           'Manage identities and access',               'RBAC', TRUE,  TRUE),
('ComplianceOfficer',  'Monitor compliance requirements',            'ABAC', FALSE, TRUE),
('FinanceViewer',      'View financial reports',                     'ABAC', FALSE, TRUE),
('DevOpsEngineer',     'CI/CD and infra management',                 'RBAC', FALSE, TRUE),
('SREEngineer',        'Site reliability engineering',               'RBAC', FALSE, TRUE),
('DBA',                'Database administration',                    'RBAC', TRUE,  TRUE),
('APIGatewayAdmin',    'Manage API gateways',                        'PBAC', FALSE, TRUE),
('SecurityAnalyst',    'Security monitoring and analysis',           'ABAC', FALSE, TRUE),
('MLEngineer',         'Machine learning workloads',                 'RBAC', FALSE, TRUE),
('ExternalContractor', 'Limited external access',                    'ABAC', FALSE, TRUE),
('ServiceAccount',     'Automated service identity',                 'RBAC', FALSE, TRUE),
-- Redundant roles (overlap with Admin/Developer)
('AdminV2',            'Redundant admin role (legacy)',              'RBAC', TRUE,  TRUE),
('DevV2',              'Redundant developer role (legacy)',          'RBAC', FALSE, TRUE),
-- Conflict roles
('ReadWriteConflict',  'Has both read-only and write permissions',   'RBAC', FALSE, TRUE),
('TempAdmin',          'Temporary admin for migration',              'RBAC', TRUE,  TRUE),
('DataSteward',        'Governance and data quality',                'ABAC', FALSE, TRUE),
('CloudArchitect',     'Cloud design and architecture',              'PBAC', TRUE,  TRUE),
('IncidentResponder',  'Handle security incidents',                  'RBAC', FALSE, TRUE),
('PenTester',          'Penetration testing',                        'RBAC', FALSE, TRUE),
('ZeroTrustRole',      'Zero-trust access only',                     'PBAC', FALSE, TRUE),
-- Orphan roles (no users assigned)
('OrphanRole1',        'Orphaned role — no users',                   'RBAC', FALSE, TRUE),
('OrphanRole2',        'Orphaned legacy role',                       'RBAC', FALSE, FALSE);

-- ─────────────────────────────────────────────
-- ROLE HIERARCHY
-- ─────────────────────────────────────────────
INSERT INTO RoleHierarchy (parent_role, child_role) VALUES
-- SuperAdmin > Admin > Developer > Guest
(1, 2),   -- SuperAdmin → Admin
(2, 3),   -- Admin → Developer
(3, 5),   -- Developer → Guest
-- SuperAdmin inherits Admin; Admin inherits network/storage/IAM
(2, 7),   -- Admin → NetworkAdmin
(2, 8),   -- Admin → StorageAdmin
(2, 9),   -- Admin → IAMAdmin
-- DevOps inherits Developer
(3, 12),  -- Developer → DevOpsEngineer
(3, 13),  -- Developer → SREEngineer
-- Auditor < ComplianceOfficer
(10, 6),  -- ComplianceOfficer → Auditor
-- SecurityAnalyst inherits Auditor
(6, 16),  -- Auditor → SecurityAnalyst
-- CloudArchitect inherits DevOps
(12, 25), -- DevOpsEngineer → CloudArchitect
-- AdminV2 mirrors Admin (redundant)
(2, 20),  -- Admin → AdminV2
-- ZeroTrustRole inherits SecurityAnalyst
(16, 28); -- SecurityAnalyst → ZeroTrustRole

-- ─────────────────────────────────────────────
-- PERMISSIONS  (40 rows)
-- ─────────────────────────────────────────────
INSERT INTO Permissions (permission_name, resource, access_level, data_sensitivity, requires_mfa, time_restricted, geo_restricted, api_permission, compliance_tag) VALUES
-- Storage
('storage.read',           'cloud-storage',          'Read',   'Public',           FALSE, FALSE, FALSE, FALSE, NULL),
('storage.write',          'cloud-storage',          'Write',  'Private',          FALSE, FALSE, FALSE, FALSE, NULL),
('storage.admin',          'cloud-storage',          'Admin',  'Confidential',     TRUE,  FALSE, FALSE, FALSE, NULL),
('storage.sensitive.read', 'cloud-storage-sensitive', 'Read',  'Highly Confidential', TRUE, TRUE, TRUE,  FALSE, 'HIPAA'),
-- IAM
('iam.read',               'iam-service',            'Read',   'Private',          FALSE, FALSE, FALSE, FALSE, NULL),
('iam.modify',             'iam-service',            'Modify', 'Confidential',     TRUE,  FALSE, FALSE, FALSE, 'SOX'),
('iam.admin',              'iam-service',            'Admin',  'Highly Confidential', TRUE, FALSE, FALSE, FALSE, 'SOX'),
-- Network
('network.read',           'vpc-network',            'Read',   'Private',          FALSE, FALSE, FALSE, FALSE, NULL),
('network.modify',         'vpc-network',            'Modify', 'Confidential',     TRUE,  FALSE, FALSE, FALSE, NULL),
('network.admin',          'vpc-network',            'Admin',  'Confidential',     TRUE,  FALSE, FALSE, FALSE, NULL),
-- Database
('db.read',                'database',               'Read',   'Confidential',     FALSE, FALSE, FALSE, FALSE, 'GDPR'),
('db.write',               'database',               'Write',  'Confidential',     TRUE,  FALSE, FALSE, FALSE, 'GDPR'),
('db.admin',               'database',               'Admin',  'Highly Confidential', TRUE, FALSE, FALSE, FALSE, 'GDPR'),
-- Audit / Logs
('logs.read',              'audit-logs',             'Read',   'Confidential',     FALSE, FALSE, FALSE, FALSE, NULL),
('logs.admin',             'audit-logs',             'Admin',  'Highly Confidential', TRUE, FALSE, FALSE, FALSE, 'SOX'),
-- API
('api.read',               'api-gateway',            'Read',   'Public',           FALSE, FALSE, FALSE, TRUE,  NULL),
('api.write',              'api-gateway',            'Write',  'Private',          FALSE, FALSE, FALSE, TRUE,  NULL),
('api.admin',              'api-gateway',            'Admin',  'Confidential',     TRUE,  FALSE, FALSE, TRUE,  NULL),
-- Compute
('compute.read',           'compute-instances',      'Read',   'Private',          FALSE, FALSE, FALSE, FALSE, NULL),
('compute.modify',         'compute-instances',      'Modify', 'Private',          FALSE, FALSE, FALSE, FALSE, NULL),
('compute.admin',          'compute-instances',      'Admin',  'Confidential',     TRUE,  FALSE, FALSE, FALSE, NULL),
-- Finance
('finance.read',           'finance-reports',        'Read',   'Highly Confidential', TRUE, TRUE,  TRUE,  FALSE, 'SOX'),
('finance.modify',         'finance-reports',        'Modify', 'Highly Confidential', TRUE, TRUE,  TRUE,  FALSE, 'SOX'),
-- ML
('ml.read',                'ml-platform',            'Read',   'Private',          FALSE, FALSE, FALSE, FALSE, NULL),
('ml.write',               'ml-platform',            'Write',  'Confidential',     FALSE, FALSE, FALSE, FALSE, NULL),
('ml.admin',               'ml-platform',            'Admin',  'Confidential',     TRUE,  FALSE, FALSE, FALSE, NULL),
-- Security
('sec.read',               'security-console',       'Read',   'Confidential',     FALSE, FALSE, FALSE, FALSE, NULL),
('sec.admin',              'security-console',       'Admin',  'Highly Confidential', TRUE, FALSE, FALSE, FALSE, 'NIST'),
-- CI/CD
('cicd.read',              'cicd-pipeline',          'Read',   'Private',          FALSE, FALSE, FALSE, TRUE,  NULL),
('cicd.write',             'cicd-pipeline',          'Write',  'Private',          FALSE, FALSE, FALSE, TRUE,  NULL),
('cicd.admin',             'cicd-pipeline',          'Admin',  'Confidential',     TRUE,  FALSE, FALSE, TRUE,  NULL),
-- Compliance
('compliance.read',        'compliance-dashboard',   'Read',   'Confidential',     FALSE, FALSE, FALSE, FALSE, 'GDPR'),
('compliance.admin',       'compliance-dashboard',   'Admin',  'Highly Confidential', TRUE, FALSE, FALSE, FALSE, 'GDPR'),
-- Serverless
('serverless.read',        'serverless-functions',   'Read',   'Private',          FALSE, FALSE, FALSE, TRUE,  NULL),
('serverless.write',       'serverless-functions',   'Write',  'Private',          FALSE, FALSE, FALSE, TRUE,  NULL),
-- Token / Session
('token.manage',           'token-service',          'Admin',  'Highly Confidential', TRUE, FALSE, FALSE, TRUE, 'OAuth'),
-- Data Governance
('governance.read',        'data-governance',        'Read',   'Confidential',     FALSE, FALSE, FALSE, FALSE, 'GDPR'),
('governance.admin',       'data-governance',        'Admin',  'Highly Confidential', TRUE, FALSE, FALSE, FALSE, 'GDPR'),
-- Pentest
('pentest.execute',        'pentest-tooling',        'Admin',  'Highly Confidential', TRUE, TRUE,  TRUE,  FALSE, NULL),
-- Readonly placeholder (conflict test)
('readonly.all',           'all-resources',          'Read',   'Public',           FALSE, FALSE, FALSE, FALSE, NULL);

-- ─────────────────────────────────────────────
-- USER ↔ ROLE  (edge cases: multi-role, orphans)
-- ─────────────────────────────────────────────
INSERT INTO UserRole (user_id, role_id, assigned_by, is_active) VALUES
-- carol (uid=3) = SuperAdmin
(3,  1,  3,  TRUE),
-- alice (uid=1) = Admin
(1,  2,  3,  TRUE),
-- frank, ulric = Developer
(6,  3,  1,  TRUE),
(24, 3,  1,  TRUE),
-- eve, vera = Analyst
(5,  4,  1,  TRUE),
(25, 4,  1,  TRUE),
-- dave, hank, will, zoe = Guest
(4,  5,  1,  TRUE),
(8,  5,  1,  TRUE),
(26, 5,  1,  TRUE),
(29, 5,  1,  TRUE),
-- jack = Auditor
(10, 6,  1,  TRUE),
-- mike = NetworkAdmin
(16, 7,  1,  TRUE),
-- nancy = StorageAdmin
(17, 8,  1,  TRUE),
-- oscar = IAMAdmin
(18, 9,  1,  TRUE),
-- ken = ComplianceOfficer
(14, 10, 1,  TRUE),
-- laura = FinanceViewer
(15, 11, 1,  TRUE),
-- iris = DevOpsEngineer
(9,  12, 1,  TRUE),
-- pam = SREEngineer
(19, 13, 1,  TRUE),
-- quinn = DBA
(20, 14, 1,  TRUE),
-- rachel = APIGatewayAdmin
(21, 15, 1,  TRUE),
-- tina = SecurityAnalyst
(23, 16, 1,  TRUE),
-- vera also = MLEngineer
(25, 17, 1,  TRUE),
-- yann = ExternalContractor
(28, 18, 1,  TRUE),
-- bots = ServiceAccount
(33, 19, 1,  TRUE),
(34, 19, 1,  TRUE),
-- adam = TempAdmin + Admin (multi-role for privilege escalation test)
(30, 2,  3,  TRUE),
(30, 23, 3,  TRUE),
-- multirole.user (uid=13) = Developer + Analyst + Guest
(13, 3,  1,  TRUE),
(13, 4,  1,  TRUE),
(13, 5,  1,  TRUE),
-- sam = CloudArchitect
(22, 25, 1,  TRUE),
-- xena = SuperAdmin + Admin (redundant assignment)
(27, 1,  3,  TRUE),
(27, 2,  3,  TRUE),
-- will also has ReadWriteConflict (conflict edge case)
(26, 22, 1,  TRUE),
-- inactive user still has a role (test case)
(12, 5,  1,  FALSE),
-- orphan.user1, orphan.user2: NO roles intentionally
-- zoe = PenTester (limited)
(29, 27, 3,  TRUE);

-- ─────────────────────────────────────────────
-- ROLE ↔ PERMISSION
-- ─────────────────────────────────────────────
INSERT INTO RolePermission (role_id, permission_id, is_active) VALUES
-- Guest (5): read-only
(5,  1,  TRUE),   -- storage.read
(5,  19, TRUE),   -- compute.read
(5,  40, TRUE),   -- readonly.all
-- Developer (3): read+write code/cicd/api
(3,  1,  TRUE),
(3,  2,  TRUE),
(3,  16, TRUE),
(3,  17, TRUE),
(3,  29, TRUE),
(3,  30, TRUE),
(3,  24, TRUE),
(3,  25, TRUE),
(3,  19, TRUE),
(3,  20, TRUE),
-- Admin (2): broad access, no super-sensitive
(2,  1,  TRUE),
(2,  2,  TRUE),
(2,  3,  TRUE),
(2,  5,  TRUE),
(2,  6,  TRUE),
(2,  8,  TRUE),
(2,  9,  TRUE),
(2,  10, TRUE),
(2,  11, TRUE),
(2,  12, TRUE),
(2,  14, TRUE),
(2,  16, TRUE),
(2,  17, TRUE),
(2,  18, TRUE),
(2,  19, TRUE),
(2,  20, TRUE),
(2,  21, TRUE),
(2,  29, TRUE),
(2,  30, TRUE),
(2,  31, TRUE),
(2,  32, TRUE),
-- SuperAdmin (1): everything
(1,  1,  TRUE),
(1,  2,  TRUE),
(1,  3,  TRUE),
(1,  4,  TRUE),
(1,  5,  TRUE),
(1,  6,  TRUE),
(1,  7,  TRUE),
(1,  8,  TRUE),
(1,  9,  TRUE),
(1,  10, TRUE),
(1,  11, TRUE),
(1,  12, TRUE),
(1,  13, TRUE),
(1,  14, TRUE),
(1,  15, TRUE),
(1,  16, TRUE),
(1,  17, TRUE),
(1,  18, TRUE),
(1,  19, TRUE),
(1,  20, TRUE),
(1,  21, TRUE),
(1,  22, TRUE),
(1,  23, TRUE),
(1,  24, TRUE),
(1,  25, TRUE),
(1,  26, TRUE),
(1,  27, TRUE),
(1,  28, TRUE),
(1,  29, TRUE),
(1,  30, TRUE),
(1,  31, TRUE),
(1,  32, TRUE),
(1,  33, TRUE),
(1,  34, TRUE),
(1,  35, TRUE),
(1,  36, TRUE),
(1,  37, TRUE),
(1,  38, TRUE),
(1,  39, TRUE),
(1,  40, TRUE),
-- Auditor (6): logs + compliance read
(6,  14, TRUE),
(6,  32, TRUE),
(6,  37, TRUE),
-- ComplianceOfficer (10): compliance + audit
(10, 14, TRUE),
(10, 32, TRUE),
(10, 33, TRUE),
(10, 37, TRUE),
(10, 38, TRUE),
-- NetworkAdmin (7)
(7,  8,  TRUE),
(7,  9,  TRUE),
(7,  10, TRUE),
-- StorageAdmin (8)
(8,  1,  TRUE),
(8,  2,  TRUE),
(8,  3,  TRUE),
(8,  4,  TRUE),
-- IAMAdmin (9)
(9,  5,  TRUE),
(9,  6,  TRUE),
(9,  7,  TRUE),
(9,  36, TRUE),
-- FinanceViewer (11): read finance only
(11, 22, TRUE),
-- DBA (14)
(14, 11, TRUE),
(14, 12, TRUE),
(14, 13, TRUE),
-- SecurityAnalyst (16)
(16, 14, TRUE),
(16, 27, TRUE),
(16, 28, TRUE),
-- DevOpsEngineer (12)
(12, 29, TRUE),
(12, 30, TRUE),
(12, 31, TRUE),
(12, 16, TRUE),
(12, 17, TRUE),
-- APIGatewayAdmin (15)
(15, 16, TRUE),
(15, 17, TRUE),
(15, 18, TRUE),
-- MLEngineer (17)
(17, 24, TRUE),
(17, 25, TRUE),
(17, 26, TRUE),
-- ExternalContractor (18): readonly only
(18, 1,  TRUE),
(18, 40, TRUE),
-- ServiceAccount (19)
(19, 16, TRUE),
(19, 19, TRUE),
-- AdminV2 (20): same as Admin — REDUNDANT
(20, 1,  TRUE),
(20, 2,  TRUE),
(20, 3,  TRUE),
(20, 5,  TRUE),
(20, 6,  TRUE),
(20, 8,  TRUE),
(20, 9,  TRUE),
(20, 10, TRUE),
(20, 11, TRUE),
(20, 12, TRUE),
(20, 14, TRUE),
(20, 16, TRUE),
(20, 17, TRUE),
(20, 18, TRUE),
(20, 19, TRUE),
(20, 20, TRUE),
(20, 21, TRUE),
(20, 29, TRUE),
(20, 30, TRUE),
(20, 31, TRUE),
(20, 32, TRUE),
-- ReadWriteConflict (22): conflict - both readonly.all AND storage.admin
(22, 40, TRUE),  -- readonly
(22, 3,  TRUE),  -- storage.admin (conflict!)
-- TempAdmin (23): Admin-equivalent temporary
(23, 1,  TRUE),
(23, 2,  TRUE),
(23, 3,  TRUE),
(23, 5,  TRUE),
(23, 6,  TRUE),
(23, 7,  TRUE),
-- ZeroTrustRole (28): strict minimum
(28, 27, TRUE),
-- PenTester (27): pentest only
(27, 39, TRUE),
(27, 27, TRUE),
-- CloudArchitect (25)
(25, 8,  TRUE),
(25, 9,  TRUE),
(25, 19, TRUE),
(25, 20, TRUE),
(25, 21, TRUE),
-- DataSteward (24)
(24, 37, TRUE),
(24, 38, TRUE),
-- SREEngineer (13)
(13, 19, TRUE),
(13, 20, TRUE),
(13, 14, TRUE),
-- Analyst (4)
(4,  1,  TRUE),
(4,  11, TRUE),
(4,  24, TRUE),
(4,  40, TRUE);

-- ─────────────────────────────────────────────
-- POLICIES  (30 rows)
-- ─────────────────────────────────────────────
INSERT INTO Policies (policy_name, description, auth_model, zero_trust, least_privilege, dlp_enabled, mfa_required, geo_restriction, time_window_start, time_window_end, compliance_tag, security_score) VALUES
('Default RBAC Policy',         'Standard RBAC for all users',                  'RBAC', FALSE, TRUE,  FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   3),
('MFA Enforcement Policy',      'Require MFA for privileged roles',             'RBAC', FALSE, TRUE,  FALSE, TRUE,  NULL,        NULL,    NULL,    NULL,   4),
('GDPR Data Access Policy',     'GDPR-compliant data access controls',          'ABAC', FALSE, TRUE,  TRUE,  FALSE, 'EU',        NULL,    NULL,    'GDPR', 4),
('HIPAA Storage Policy',        'HIPAA-compliant storage access',               'ABAC', FALSE, TRUE,  TRUE,  TRUE,  NULL,        NULL,    NULL,    'HIPAA',5),
('Zero Trust Network Policy',   'ZTA-based network access',                     'PBAC', TRUE,  TRUE,  FALSE, TRUE,  NULL,        NULL,    NULL,    NULL,   5),
('Time-Window Admin Policy',    'Admin access restricted to business hours',    'RBAC', FALSE, TRUE,  FALSE, TRUE,  NULL,        '08:00', '18:00', NULL,   3),
('Geo-Restricted Finance',      'Finance access limited to US/UK',              'ABAC', FALSE, TRUE,  TRUE,  TRUE,  'US,UK',     NULL,    NULL,    'SOX',  5),
('Least Privilege Base',        'Minimal permissions for all service accounts', 'RBAC', FALSE, TRUE,  FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   3),
('External Contractor Policy',  'Tightly scoped access for contractors',        'ABAC', TRUE,  TRUE,  FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   3),
('Developer Sandbox Policy',    'Developer access in sandbox env only',         'RBAC', FALSE, TRUE,  FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   2),
('API Security Policy',         'OAuth/JWT enforcement for API access',         'PBAC', FALSE, TRUE,  FALSE, TRUE,  NULL,        NULL,    NULL,    'OAuth',4),
('SOX Compliance Policy',       'Segregation of duties for finance',            'ABAC', FALSE, TRUE,  TRUE,  TRUE,  NULL,        NULL,    NULL,    'SOX',  5),
('DLP Enforcement Policy',      'Data Loss Prevention for sensitive data',      'ABAC', FALSE, TRUE,  TRUE,  FALSE, NULL,        NULL,    NULL,    'GDPR', 4),
('Infrastructure as Code',      'Access control via Terraform / IaC',          'RBAC', FALSE, TRUE,  FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   3),
('Kubernetes Access Policy',    'RBAC for Kubernetes workloads',                'RBAC', FALSE, TRUE,  FALSE, TRUE,  NULL,        NULL,    NULL,    NULL,   4),
('Serverless Function Policy',  'Access controls for serverless functions',     'PBAC', FALSE, TRUE,  FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   3),
('Audit Log Read Policy',       'Read-only audit log access for compliance',    'RBAC', FALSE, TRUE,  FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   3),
('PenTest Execution Policy',    'Controlled pentest with time restrictions',    'RBAC', FALSE, FALSE, FALSE, TRUE,  NULL,        '09:00', '17:00', NULL,   5),
('Multi-Tenant Isolation',      'Segregation between tenants',                  'ABAC', TRUE,  TRUE,  TRUE,  FALSE, NULL,        NULL,    NULL,    NULL,   4),
('Cloud Storage Public Policy', 'Public read for designated buckets',           'RBAC', FALSE, FALSE, FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   2),
('Token Rotation Policy',       'JWT / OAuth token rotation requirements',      'PBAC', TRUE,  TRUE,  FALSE, TRUE,  NULL,        NULL,    NULL,    'OAuth',4),
('Account Lockout Policy',      'Lock after 5 failed login attempts',           'RBAC', FALSE, TRUE,  FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   3),
('Dynamic Risk Access Policy',  'Real-time risk-based access adjustment',       'PBAC', TRUE,  TRUE,  FALSE, TRUE,  NULL,        NULL,    NULL,    NULL,   5),
('Cross-Region Replication',    'Cross-region storage and access policy',       'RBAC', FALSE, TRUE,  FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   3),
('VPC Segmentation Policy',     'VPC boundary enforcement',                     'RBAC', FALSE, TRUE,  FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   3),
('Identity Federation Policy',  'External IdP (Okta/AzureAD) integration',     'ABAC', FALSE, TRUE,  FALSE, TRUE,  NULL,        NULL,    NULL,    NULL,   4),
('Instance Metadata Policy',    'Restrict IMDS access',                         'RBAC', FALSE, TRUE,  FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   4),
('Shared Responsibility Model', 'CSP vs customer responsibility boundaries',    'RBAC', FALSE, TRUE,  FALSE, FALSE, NULL,        NULL,    NULL,    NULL,   3),
('Data Governance Framework',   'Global data access governance',                'ABAC', FALSE, TRUE,  TRUE,  FALSE, NULL,        NULL,    NULL,    'GDPR', 4),
('Privilege Escalation Guard',  'Prevent unauthorized privilege escalation',    'PBAC', TRUE,  TRUE,  FALSE, TRUE,  NULL,        NULL,    NULL,    NULL,   5);

-- ─────────────────────────────────────────────
-- POLICY ↔ ROLE
-- ─────────────────────────────────────────────
INSERT INTO PolicyRole (policy_id, role_id) VALUES
(1,  5),  -- Default → Guest
(1,  3),  -- Default → Developer
(1,  4),  -- Default → Analyst
(2,  2),  -- MFA → Admin
(2,  1),  -- MFA → SuperAdmin
(3,  10), -- GDPR → ComplianceOfficer
(3,  6),  -- GDPR → Auditor
(4,  8),  -- HIPAA → StorageAdmin
(5,  28), -- ZeroTrust → ZeroTrustRole
(5,  16), -- ZeroTrust → SecurityAnalyst
(6,  2),  -- TimeWindow → Admin
(7,  11), -- GeoFinance → FinanceViewer
(8,  19), -- LeastPriv → ServiceAccount
(8,  18), -- LeastPriv → ExternalContractor
(9,  18), -- ExtContractor → ExternalContractor
(10, 3),  -- Sandbox → Developer
(11, 15), -- API → APIGatewayAdmin
(12, 11), -- SOX → FinanceViewer
(13, 10), -- DLP → ComplianceOfficer
(14, 12), -- IaC → DevOpsEngineer
(15, 12), -- K8s → DevOpsEngineer
(16, 19), -- Serverless → ServiceAccount
(17, 6),  -- AuditRead → Auditor
(18, 27), -- PenTest → PenTester
(19, 9),  -- MultiTenant → IAMAdmin
(20, 5),  -- Public → Guest
(21, 15), -- Token → APIGatewayAdmin
(22, 5),  -- Lockout → Guest
(23, 25), -- Dynamic → CloudArchitect
(24, 8),  -- CrossRegion → StorageAdmin
(25, 7),  -- VPC → NetworkAdmin
(26, 9),  -- Federation → IAMAdmin
(27, 19), -- IMDS → ServiceAccount
(28, 1),  -- SharedResp → SuperAdmin
(29, 24), -- DataGov → DataSteward
(30, 1);  -- PrivEscGuard → SuperAdmin

-- ─────────────────────────────────────────────
-- SESSIONS  (35 rows)
-- ─────────────────────────────────────────────
INSERT INTO Sessions (user_id, session_token, ip_address, geolocation, cloud_provider, auth_mechanism, started_at, expires_at, is_active) VALUES
(1,  'tok_alice_001',  '10.0.0.1',  'US',        'AWS',       'MFA',       NOW() - INTERVAL '2 hours',  NOW() + INTERVAL '6 hours', TRUE),
(2,  'tok_bob_001',    '10.0.0.2',  'Germany',   'Azure',     'Password',  NOW() - INTERVAL '1 hour',   NOW() + INTERVAL '7 hours', TRUE),
(3,  'tok_carol_001',  '10.0.0.3',  'US',        'GCP',       'MFA',       NOW() - INTERVAL '30 min',   NOW() + INTERVAL '8 hours', TRUE),
(4,  'tok_dave_001',   '10.0.0.4',  'India',     'AWS',       'SSO',       NOW() - INTERVAL '3 hours',  NOW() - INTERVAL '1 hour',  FALSE),
(5,  'tok_eve_001',    '10.0.0.5',  'UK',        'Azure',     'Biometric', NOW() - INTERVAL '1 hour',   NOW() + INTERVAL '7 hours', TRUE),
(6,  'tok_frank_001',  '10.0.0.6',  'Australia', 'GCP',       'MFA',       NOW() - INTERVAL '4 hours',  NOW() + INTERVAL '4 hours', TRUE),
(7,  'tok_grace_001',  '10.0.0.7',  'US',        'AWS',       'SSO',       NOW() - INTERVAL '2 hours',  NOW() + INTERVAL '6 hours', TRUE),
(8,  'tok_hank_001',   '10.0.0.8',  'Germany',   'IBM Cloud', 'Password',  NOW() - INTERVAL '5 hours',  NOW() + INTERVAL '3 hours', TRUE),
(9,  'tok_iris_001',   '10.0.0.9',  'US',        'AWS',       'MFA',       NOW() - INTERVAL '1 hour',   NOW() + INTERVAL '7 hours', TRUE),
(10, 'tok_jack_001',   '10.0.0.10', 'UK',        'Azure',     'Biometric', NOW() - INTERVAL '2 hours',  NOW() + INTERVAL '6 hours', TRUE),
(13, 'tok_multi_001',  '10.0.0.13', 'US',        'AWS',       'MFA',       NOW() - INTERVAL '1 hour',   NOW() + INTERVAL '7 hours', TRUE),
(14, 'tok_ken_001',    '10.0.0.14', 'Germany',   'Azure',     'MFA',       NOW() - INTERVAL '2 hours',  NOW() + INTERVAL '6 hours', TRUE),
(15, 'tok_laura_001',  '10.0.0.15', 'US',        'GCP',       'SSO',       NOW() - INTERVAL '1 hour',   NOW() + INTERVAL '7 hours', TRUE),
(16, 'tok_mike_001',   '10.0.0.16', 'UK',        'AWS',       'MFA',       NOW() - INTERVAL '3 hours',  NOW() + INTERVAL '5 hours', TRUE),
(17, 'tok_nancy_001',  '10.0.0.17', 'Australia', 'Azure',     'Biometric', NOW() - INTERVAL '1 hour',   NOW() + INTERVAL '7 hours', TRUE),
(18, 'tok_oscar_001',  '10.0.0.18', 'US',        'GCP',       'MFA',       NOW() - INTERVAL '2 hours',  NOW() + INTERVAL '6 hours', TRUE),
(19, 'tok_pam_001',    '10.0.0.19', 'US',        'IBM Cloud', 'SSO',       NOW() - INTERVAL '4 hours',  NOW() + INTERVAL '4 hours', TRUE),
(20, 'tok_quinn_001',  '10.0.0.20', 'Germany',   'AWS',       'MFA',       NOW() - INTERVAL '1 hour',   NOW() + INTERVAL '7 hours', TRUE),
(21, 'tok_rachel_001', '10.0.0.21', 'UK',        'Azure',     'SSO',       NOW() - INTERVAL '3 hours',  NOW() + INTERVAL '5 hours', TRUE),
(22, 'tok_sam_001',    '10.0.0.22', 'US',        'GCP',       'MFA',       NOW() - INTERVAL '2 hours',  NOW() + INTERVAL '6 hours', TRUE),
(23, 'tok_tina_001',   '10.0.0.23', 'US',        'AWS',       'MFA',       NOW() - INTERVAL '1 hour',   NOW() + INTERVAL '7 hours', TRUE),
(24, 'tok_ulric_001',  '10.0.0.24', 'Germany',   'Azure',     'SSO',       NOW() - INTERVAL '2 hours',  NOW() + INTERVAL '6 hours', TRUE),
(25, 'tok_vera_001',   '10.0.0.25', 'India',     'GCP',       'Biometric', NOW() - INTERVAL '1 hour',   NOW() + INTERVAL '7 hours', TRUE),
(26, 'tok_will_001',   '10.0.0.26', 'UK',        'IBM Cloud', 'Password',  NOW() - INTERVAL '3 hours',  NOW() + INTERVAL '5 hours', TRUE),
(27, 'tok_xena_001',   '10.0.0.27', 'US',        'AWS',       'MFA',       NOW() - INTERVAL '2 hours',  NOW() + INTERVAL '6 hours', TRUE),
(28, 'tok_yann_001',   '10.0.0.28', 'France',    'Azure',     'SSO',       NOW() - INTERVAL '1 hour',   NOW() + INTERVAL '7 hours', TRUE),
(29, 'tok_zoe_001',    '10.0.0.29', 'US',        'GCP',       'Password',  NOW() - INTERVAL '4 hours',  NOW() + INTERVAL '4 hours', TRUE),
(30, 'tok_adam_001',   '10.0.0.30', 'US',        'AWS',       'MFA',       NOW() - INTERVAL '30 min',   NOW() + INTERVAL '8 hours', TRUE),
(33, 'tok_bot1_001',   '10.0.1.1',  NULL,        'AWS',       'MFA',       NOW() - INTERVAL '6 hours',  NOW() + INTERVAL '2 hours', TRUE),
(34, 'tok_bot2_001',   '10.0.1.2',  NULL,        'GCP',       'MFA',       NOW() - INTERVAL '6 hours',  NOW() + INTERVAL '2 hours', TRUE),
-- Expired sessions
(4,  'tok_dave_exp',   '10.0.0.4',  'India',     'AWS',       'SSO',       NOW() - INTERVAL '25 hours', NOW() - INTERVAL '17 hours',FALSE),
(8,  'tok_hank_exp',   '10.0.0.8',  'Germany',   'IBM Cloud', 'Password',  NOW() - INTERVAL '48 hours', NOW() - INTERVAL '40 hours',FALSE),
-- Suspicious: no geolocation
(11, 'tok_locked_001', '192.168.1.1',NULL,       'GCP',       'Password',  NOW() - INTERVAL '2 hours',  NOW() - INTERVAL '1 hour',  FALSE),
-- New session from unusual location
(26, 'tok_will_002',   '203.0.113.5','China',    'IBM Cloud', 'Password',  NOW() - INTERVAL '30 min',   NOW() + INTERVAL '8 hours', TRUE),
(1,  'tok_alice_002',  '10.0.0.1',  'US',        'AWS',       'MFA',       NOW() - INTERVAL '1 hour',   NOW() + INTERVAL '7 hours', TRUE);

-- ─────────────────────────────────────────────
-- PRIVILEGE ESCALATION REQUESTS
-- ─────────────────────────────────────────────
INSERT INTO PrivilegeRequests (requestor_id, target_role_id, justification, status, reviewed_by, reviewed_at) VALUES
(4,  2,  'Need admin access for project X',         'DENIED',   1, NOW() - INTERVAL '5 days'),
(6,  2,  'Deploy to production requires Admin',     'APPROVED', 1, NOW() - INTERVAL '3 days'),
(8,  3,  'Need write access for feature Y',         'PENDING',  NULL, NULL),
(26, 3,  'Temporary write access for migration',   'APPROVED', 3, NOW() - INTERVAL '1 day'),
(29, 2,  'Admin access for pentest audit',          'DENIED',   3, NOW() - INTERVAL '2 days'),
(13, 1,  'Emergency super admin needed',            'DENIED',   3, NOW() - INTERVAL '1 day'),
(28, 3,  'Contractor needs dev access',             'PENDING',  NULL, NULL),
(25, 2,  'ML infra requires admin permissions',     'APPROVED', 1, NOW() - INTERVAL '4 days');

-- ─────────────────────────────────────────────
-- AUDIT LOGS  (30 initial rows via manual insert)
-- ─────────────────────────────────────────────
INSERT INTO AuditLogs (user_id, role_id, action, table_name, record_id, old_values, new_values, ip_address, performed_at) VALUES
(3,  1,  'INSERT', 'UserRole',    1,  NULL,                                    '{"role_id":1,"user_id":3}',        '10.0.0.3',  NOW() - INTERVAL '30 days'),
(3,  1,  'INSERT', 'UserRole',    2,  NULL,                                    '{"role_id":2,"user_id":1}',        '10.0.0.3',  NOW() - INTERVAL '29 days'),
(1,  2,  'INSERT', 'UserRole',    3,  NULL,                                    '{"role_id":3,"user_id":6}',        '10.0.0.1',  NOW() - INTERVAL '28 days'),
(1,  2,  'UPDATE', 'Users',       11, '{"account_locked":false}',              '{"account_locked":true}',          '10.0.0.1',  NOW() - INTERVAL '10 days'),
(1,  2,  'INSERT', 'UserRole',    7,  NULL,                                    '{"role_id":5,"user_id":4}',        '10.0.0.1',  NOW() - INTERVAL '27 days'),
(3,  1,  'INSERT', 'RolePermission',50, NULL,                                  '{"role_id":1,"permission_id":7}',  '10.0.0.3',  NOW() - INTERVAL '25 days'),
(1,  2,  'DELETE', 'UserRole',    12, '{"role_id":5,"user_id":12}',           NULL,                               '10.0.0.1',  NOW() - INTERVAL '20 days'),
(18, 9,  'INSERT', 'UserRole',    25, NULL,                                    '{"role_id":19,"user_id":33}',      '10.0.0.18', NOW() - INTERVAL '15 days'),
(3,  1,  'INSERT', 'RoleHierarchy',1, NULL,                                   '{"parent":1,"child":2}',           '10.0.0.3',  NOW() - INTERVAL '30 days'),
(1,  2,  'UPDATE', 'Roles',       30, '{"is_active":true}',                   '{"is_active":false}',              '10.0.0.1',  NOW() - INTERVAL '5 days'),
(30, 2,  'INSERT', 'UserRole',    NULL, NULL,                                  '{"role_id":23,"user_id":30}',      '10.0.0.30', NOW() - INTERVAL '2 days'),
(3,  1,  'UPDATE', 'Users',       30, '{"account_locked":false}',             '{"account_locked":false}',         '10.0.0.3',  NOW() - INTERVAL '1 day'),
(1,  2,  'INSERT', 'PolicyRole',  1,  NULL,                                   '{"policy_id":1,"role_id":5}',      '10.0.0.1',  NOW() - INTERVAL '20 days'),
(23, 16, 'INSERT', 'Sessions',    23, NULL,                                   '{"session_token":"tok_tina_001"}', '10.0.0.23', NOW() - INTERVAL '1 hour'),
(27, 1,  'INSERT', 'UserRole',    31, NULL,                                   '{"role_id":1,"user_id":27}',       '10.0.0.27', NOW() - INTERVAL '3 days'),
(1,  2,  'UPDATE', 'Permissions', 22, '{"is_active":true}',                  '{"geo_restricted":true}',          '10.0.0.1',  NOW() - INTERVAL '7 days'),
(3,  1,  'INSERT', 'Policies',    30, NULL,                                   '{"policy_name":"PrivEscGuard"}',   '10.0.0.3',  NOW() - INTERVAL '14 days'),
(6,  3,  'INSERT', 'PrivilegeRequests',2, NULL,                               '{"status":"PENDING"}',             '10.0.0.6',  NOW() - INTERVAL '4 days'),
(1,  2,  'UPDATE', 'PrivilegeRequests',2,'{"status":"PENDING"}',              '{"status":"APPROVED"}',            '10.0.0.1',  NOW() - INTERVAL '3 days'),
(4,  5,  'INSERT', 'Sessions',    4,  NULL,                                   '{"session_token":"tok_dave_001"}', '10.0.0.4',  NOW() - INTERVAL '3 hours'),
(9,  12, 'UPDATE', 'Sessions',    9,  '{"is_active":true}',                  '{"is_active":true}',               '10.0.0.9',  NOW() - INTERVAL '30 min'),
(25, 17, 'INSERT', 'UserRole',    22, NULL,                                   '{"role_id":17,"user_id":25}',      '10.0.0.25', NOW() - INTERVAL '6 days'),
(3,  1,  'DELETE', 'Sessions',    31, '{"session_token":"tok_locked_001"}',  NULL,                               '10.0.0.3',  NOW() - INTERVAL '1 hour'),
(1,  2,  'UPDATE', 'Users',       26, '{"failed_login_count":2}',            '{"failed_login_count":3}',         '10.0.0.1',  NOW() - INTERVAL '12 hours'),
(10, 6,  'INSERT', 'AuditLogs',   NULL, NULL,                                NULL,                               '10.0.0.10', NOW() - INTERVAL '2 hours'),
(3,  1,  'UPDATE', 'RolePermission',1,'{"is_active":true}',                  '{"is_active":true}',               '10.0.0.3',  NOW() - INTERVAL '1 day'),
(18, 9,  'INSERT', 'UserRole',    26, NULL,                                   '{"role_id":19,"user_id":34}',      '10.0.0.18', NOW() - INTERVAL '10 days'),
(1,  2,  'INSERT', 'PolicyRole',  36, NULL,                                   '{"policy_id":30,"role_id":1}',     '10.0.0.1',  NOW() - INTERVAL '14 days'),
(14, 10, 'INSERT', 'Sessions',    14, NULL,                                   '{"session_token":"tok_ken_001"}',  '10.0.0.14', NOW() - INTERVAL '2 hours'),
(15, 11, 'INSERT', 'Sessions',    15, NULL,                                   '{"session_token":"tok_laura_001"}','10.0.0.15', NOW() - INTERVAL '1 hour');

-- Fix ended_at for expired sessions seeded without it
UPDATE Sessions SET ended_at = expires_at WHERE is_active = FALSE;
