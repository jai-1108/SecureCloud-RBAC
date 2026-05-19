-- ============================================================
-- RBAC System — views.sql
-- ============================================================

-- ─────────────────────────────────────────────
-- V1: EffectivePermissionsView
-- Each user's resolved permissions (direct + hierarchy-inherited)
-- ─────────────────────────────────────────────
CREATE OR REPLACE VIEW EffectivePermissionsView AS
WITH RECURSIVE role_tree AS (
    SELECT ur.user_id,
           ur.role_id,
           0          AS depth,
           r.role_name,
           r.is_privileged
    FROM   UserRole ur
    JOIN   Roles    r ON r.role_id = ur.role_id
    WHERE  ur.is_active = TRUE AND r.is_active = TRUE

    UNION ALL

    SELECT rt.user_id,
           rh.parent_role,
           rt.depth + 1,
           r.role_name,
           r.is_privileged
    FROM   role_tree     rt
    JOIN   RoleHierarchy rh ON rh.child_role = rt.role_id
    JOIN   Roles          r ON r.role_id     = rh.parent_role
    WHERE  rt.depth < 10
)
SELECT DISTINCT
    u.user_id,
    u.username,
    u.email,
    u.auth_mechanism,
    rt.role_name,
    rt.is_privileged      AS role_is_privileged,
    rt.depth              AS inheritance_depth,
    p.permission_id,
    p.permission_name,
    p.resource,
    p.access_level,
    p.data_sensitivity,
    p.requires_mfa,
    p.compliance_tag,
    p.api_permission
FROM   role_tree      rt
JOIN   Users          u  ON u.user_id       = rt.user_id AND u.is_active = TRUE
JOIN   RolePermission rp ON rp.role_id      = rt.role_id AND rp.is_active = TRUE
JOIN   Permissions    p  ON p.permission_id = rp.permission_id AND p.is_active = TRUE;


-- ─────────────────────────────────────────────
-- V2: UserRoleSummaryView
-- Quick summary of each user's role assignments
-- ─────────────────────────────────────────────
CREATE OR REPLACE VIEW UserRoleSummaryView AS
SELECT
    u.user_id,
    u.username,
    u.email,
    u.auth_mechanism,
    u.is_active,
    u.account_locked,
    COUNT(DISTINCT ur.role_id)              AS role_count,
    BOOL_OR(r.is_privileged)               AS has_privileged_role,
    STRING_AGG(DISTINCT r.role_name, ', '
               ORDER BY r.role_name)        AS roles
FROM   Users    u
LEFT JOIN UserRole ur ON ur.user_id = u.user_id AND ur.is_active = TRUE
LEFT JOIN Roles    r  ON r.role_id  = ur.role_id
GROUP  BY u.user_id, u.username, u.email, u.auth_mechanism,
          u.is_active, u.account_locked;


-- ─────────────────────────────────────────────
-- V3: ActiveSessionView
-- All currently active sessions enriched with user/role info
-- ─────────────────────────────────────────────
CREATE OR REPLACE VIEW ActiveSessionView AS
SELECT
    s.session_id,
    u.username,
    s.ip_address,
    s.geolocation,
    s.auth_mechanism   AS session_auth,
    s.cloud_provider,
    s.started_at,
    s.expires_at,
    STRING_AGG(DISTINCT r.role_name, ', ') AS active_roles
FROM   Sessions   s
JOIN   Users      u  ON u.user_id  = s.user_id
LEFT JOIN UserRole ur ON ur.user_id = s.user_id AND ur.is_active = TRUE
LEFT JOIN Roles    r  ON r.role_id  = ur.role_id
WHERE  s.is_active = TRUE
  AND  s.expires_at > NOW()
GROUP  BY s.session_id, u.username, s.ip_address, s.geolocation,
          s.auth_mechanism, s.cloud_provider, s.started_at, s.expires_at;


-- ─────────────────────────────────────────────
-- V4: PermissionConflictView
-- Roles with Read and Admin permissions on the same resource
-- ─────────────────────────────────────────────
CREATE OR REPLACE VIEW PermissionConflictView AS
SELECT
    r.role_id,
    r.role_name,
    p1.resource,
    p1.permission_name AS admin_permission,
    p2.permission_name AS read_permission,
    'READ_ADMIN_CONFLICT' AS conflict_type
FROM   Roles          r
JOIN   RolePermission rp1 ON rp1.role_id      = r.role_id AND rp1.is_active = TRUE
JOIN   Permissions    p1  ON p1.permission_id  = rp1.permission_id AND p1.access_level = 'Admin'
JOIN   RolePermission rp2 ON rp2.role_id      = r.role_id AND rp2.is_active = TRUE
JOIN   Permissions    p2  ON p2.permission_id  = rp2.permission_id AND p2.access_level = 'Read'
WHERE  p1.resource = p2.resource
  AND  p1.permission_id <> p2.permission_id;


-- ─────────────────────────────────────────────
-- V5: ComplianceDashboardView
-- Per-role compliance coverage across GDPR, HIPAA, SOX
-- ─────────────────────────────────────────────
CREATE OR REPLACE VIEW ComplianceDashboardView AS
SELECT
    r.role_name,
    r.auth_model,
    r.is_privileged,
    pol.compliance_tag,
    COUNT(DISTINCT p.permission_id)         AS total_permissions,
    COUNT(DISTINCT pr.policy_id)            AS policies_applied,
    ROUND(AVG(pol.security_score), 1)       AS avg_policy_score
FROM   Roles          r
LEFT JOIN RolePermission rp  ON rp.role_id     = r.role_id AND rp.is_active = TRUE
LEFT JOIN Permissions    p   ON p.permission_id = rp.permission_id
LEFT JOIN PolicyRole     pr  ON pr.role_id     = r.role_id
LEFT JOIN Policies       pol ON pol.policy_id  = pr.policy_id AND pol.is_active = TRUE
WHERE  r.is_active = TRUE
GROUP  BY r.role_name, r.auth_model, r.is_privileged, pol.compliance_tag;
