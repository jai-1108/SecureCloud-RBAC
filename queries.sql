-- ============================================================
-- RBAC System — queries.sql
-- 25 Complex Queries + 10 Disjoint (Set-Based) Queries
-- ============================================================

-- ════════════════════════════════════════════════
-- SECTION A: COMPLEX QUERIES (1–25)
-- ════════════════════════════════════════════════

-- ─────────────────────────────────────────────
-- Q1: EFFECTIVE PERMISSIONS per user (direct + inherited via role hierarchy)
-- Technique: Recursive CTE + multi-table join (5 tables)
-- ─────────────────────────────────────────────
WITH RECURSIVE role_tree AS (
    -- Base: direct roles assigned to the user
    SELECT ur.user_id, ur.role_id, 0 AS depth
    FROM   UserRole ur
    WHERE  ur.is_active = TRUE

    UNION ALL

    -- Recursive: parent roles via hierarchy
    SELECT rt.user_id, rh.parent_role AS role_id, rt.depth + 1
    FROM   role_tree rt
    JOIN   RoleHierarchy rh ON rh.child_role = rt.role_id
    WHERE  rt.depth < 10  -- prevent infinite recursion
),
effective AS (
    SELECT DISTINCT rt.user_id,
                    p.permission_id,
                    p.permission_name,
                    p.resource,
                    p.access_level,
                    p.data_sensitivity,
                    r.role_name,
                    rt.depth
    FROM   role_tree rt
    JOIN   RolePermission rp ON rp.role_id = rt.role_id AND rp.is_active = TRUE
    JOIN   Permissions    p  ON p.permission_id = rp.permission_id AND p.is_active = TRUE
    JOIN   Roles          r  ON r.role_id = rt.role_id
)
SELECT u.user_id,
       u.username,
       e.role_name,
       e.depth            AS inheritance_depth,
       e.permission_name,
       e.resource,
       e.access_level,
       e.data_sensitivity
FROM   effective e
JOIN   Users u ON u.user_id = e.user_id
ORDER  BY u.username, e.depth, e.permission_name;


-- ─────────────────────────────────────────────
-- Q2: LEAST PRIVILEGE VIOLATIONS
-- Users who have Admin-level permissions but are NOT in a privileged role
-- Technique: correlated subquery + 3-table join
-- ─────────────────────────────────────────────
SELECT u.user_id,
       u.username,
       r.role_name,
       p.permission_name,
       p.access_level
FROM   Users          u
JOIN   UserRole       ur ON ur.user_id = u.user_id AND ur.is_active = TRUE
JOIN   Roles          r  ON r.role_id  = ur.role_id AND r.is_privileged = FALSE
JOIN   RolePermission rp ON rp.role_id = r.role_id  AND rp.is_active = TRUE
JOIN   Permissions    p  ON p.permission_id = rp.permission_id
WHERE  p.access_level = 'Admin'
  AND  NOT EXISTS (
           SELECT 1
           FROM   UserRole       ur2
           JOIN   Roles          r2 ON r2.role_id = ur2.role_id
           WHERE  ur2.user_id    = u.user_id
             AND  r2.is_privileged = TRUE
             AND  ur2.is_active  = TRUE
       )
ORDER  BY u.username;


-- ─────────────────────────────────────────────
-- Q3: ROLE HIERARCHY TRAVERSAL — full ancestor chain for each role
-- Technique: Recursive CTE (WITH RECURSIVE)
-- ─────────────────────────────────────────────
WITH RECURSIVE ancestors AS (
    SELECT role_id       AS start_role,
           role_id       AS ancestor_id,
           0             AS level,
           role_name     AS ancestor_name
    FROM   Roles

    UNION ALL

    SELECT a.start_role,
           rh.parent_role,
           a.level + 1,
           r.role_name
    FROM   ancestors     a
    JOIN   RoleHierarchy rh ON rh.child_role  = a.ancestor_id
    JOIN   Roles         r  ON r.role_id      = rh.parent_role
    WHERE  a.level < 10
)
SELECT r.role_name    AS role,
       a.ancestor_name AS ancestor,
       a.level         AS levels_up
FROM   ancestors a
JOIN   Roles     r ON r.role_id = a.start_role
WHERE  a.level > 0
ORDER  BY r.role_name, a.level;


-- ─────────────────────────────────────────────
-- Q4: PERMISSION COVERAGE — roles that cover ALL sensitive permissions
-- Technique: Division query (relational division)
-- ─────────────────────────────────────────────
SELECT r.role_id, r.role_name
FROM   Roles r
WHERE  NOT EXISTS (
    -- All highly-confidential permissions…
    SELECT p.permission_id
    FROM   Permissions p
    WHERE  p.data_sensitivity = 'Highly Confidential'
      AND  p.is_active = TRUE
    -- …that this role does NOT have
    EXCEPT
    SELECT rp.permission_id
    FROM   RolePermission rp
    WHERE  rp.role_id = r.role_id
      AND  rp.is_active = TRUE
)
ORDER  BY r.role_name;


-- ─────────────────────────────────────────────
-- Q5: CONFLICT DETECTION — roles with both Read-only and Admin on the same resource
-- Technique: Self-join on RolePermission
-- ─────────────────────────────────────────────
SELECT r.role_name,
       p1.resource,
       p1.permission_name AS admin_permission,
       p2.permission_name AS read_permission
FROM   Roles          r
JOIN   RolePermission rp1 ON rp1.role_id = r.role_id AND rp1.is_active = TRUE
JOIN   Permissions    p1  ON p1.permission_id = rp1.permission_id AND p1.access_level = 'Admin'
JOIN   RolePermission rp2 ON rp2.role_id = r.role_id AND rp2.is_active = TRUE
JOIN   Permissions    p2  ON p2.permission_id = rp2.permission_id AND p2.access_level = 'Read'
WHERE  p1.resource = p2.resource
  AND  p1.permission_id <> p2.permission_id
ORDER  BY r.role_name, p1.resource;


-- ─────────────────────────────────────────────
-- Q6: REDUNDANT ROLES — roles with identical permission sets
-- Technique: Aggregation + HAVING, correlated subquery
-- ─────────────────────────────────────────────
SELECT r1.role_name AS role_a,
       r2.role_name AS role_b,
       COUNT(*)      AS shared_permissions
FROM   Roles          r1
JOIN   Roles          r2 ON r1.role_id < r2.role_id
JOIN   RolePermission rp1 ON rp1.role_id = r1.role_id AND rp1.is_active = TRUE
JOIN   RolePermission rp2 ON rp2.role_id = r2.role_id
                          AND rp2.permission_id = rp1.permission_id
                          AND rp2.is_active = TRUE
GROUP  BY r1.role_name, r2.role_name
HAVING COUNT(*) = (
    SELECT COUNT(*) FROM RolePermission rp
    WHERE  rp.role_id = r1.role_id AND rp.is_active = TRUE
)
   AND COUNT(*) = (
    SELECT COUNT(*) FROM RolePermission rp
    WHERE  rp.role_id = r2.role_id AND rp.is_active = TRUE
)
ORDER  BY shared_permissions DESC;


-- ─────────────────────────────────────────────
-- Q7: PRIVILEGE ESCALATION PATHS
-- Users with APPROVED privilege requests that granted them a role they didn't hold before
-- Technique: Anti-join (NOT EXISTS), 4-table join
-- ─────────────────────────────────────────────
SELECT u.username,
       r.role_name       AS escalated_to,
       pr.justification,
       pr.requested_at,
       pr.reviewed_at,
       reviewer.username AS reviewed_by
FROM   PrivilegeRequests pr
JOIN   Users u        ON u.user_id        = pr.requestor_id
JOIN   Roles r        ON r.role_id        = pr.target_role_id
JOIN   Users reviewer ON reviewer.user_id = pr.reviewed_by
WHERE  pr.status = 'APPROVED'
  AND  NOT EXISTS (
           SELECT 1
           FROM   UserRole ur
           WHERE  ur.user_id = pr.requestor_id
             AND  ur.role_id = pr.target_role_id
             AND  (ur.assigned_at < pr.requested_at OR ur.assigned_at IS NULL)
       )
ORDER  BY pr.reviewed_at DESC;


-- ─────────────────────────────────────────────
-- Q8: USER RANKING by number of effective permissions (window function)
-- Technique: RANK() / DENSE_RANK() window functions, CTE
-- ─────────────────────────────────────────────
WITH perm_counts AS (
    SELECT ur.user_id,
           COUNT(DISTINCT rp.permission_id) AS perm_count
    FROM   UserRole       ur
    JOIN   RolePermission rp ON rp.role_id = ur.role_id AND rp.is_active = TRUE
    WHERE  ur.is_active = TRUE
    GROUP  BY ur.user_id
)
SELECT u.username,
       pc.perm_count,
       RANK()        OVER (ORDER BY pc.perm_count DESC) AS rank,
       DENSE_RANK()  OVER (ORDER BY pc.perm_count DESC) AS dense_rank,
       PERCENT_RANK() OVER (ORDER BY pc.perm_count DESC) AS percentile
FROM   perm_counts pc
JOIN   Users u ON u.user_id = pc.user_id
ORDER  BY pc.perm_count DESC;


-- ─────────────────────────────────────────────
-- Q9: ACTIVE SESSIONS with role context + session risk score
-- High risk = Password auth + sensitive permission + no MFA
-- Technique: CASE expression + multi-join (5 tables)
-- ─────────────────────────────────────────────
SELECT s.session_id,
       u.username,
       s.auth_mechanism,
       s.geolocation,
       r.role_name,
       p.data_sensitivity,
       CASE
           WHEN s.auth_mechanism IN ('Password', 'SSO')
                AND p.data_sensitivity IN ('Confidential','Highly Confidential')
                AND p.requires_mfa = TRUE
           THEN 'HIGH'
           WHEN s.auth_mechanism IN ('Password','SSO')
                AND p.data_sensitivity = 'Confidential'
           THEN 'MEDIUM'
           ELSE 'LOW'
       END AS session_risk
FROM   Sessions       s
JOIN   Users          u  ON u.user_id        = s.user_id
JOIN   UserRole       ur ON ur.user_id        = u.user_id AND ur.is_active = TRUE
JOIN   Roles          r  ON r.role_id         = ur.role_id
JOIN   RolePermission rp ON rp.role_id        = r.role_id AND rp.is_active = TRUE
JOIN   Permissions    p  ON p.permission_id   = rp.permission_id
WHERE  s.is_active = TRUE
ORDER  BY session_risk DESC, u.username;


-- ─────────────────────────────────────────────
-- Q10: POLICY COVERAGE GAPS — roles that have NO associated policy
-- Technique: Anti-join (NOT EXISTS), 2-table join
-- ─────────────────────────────────────────────
SELECT r.role_id,
       r.role_name,
       r.auth_model,
       r.is_privileged
FROM   Roles r
WHERE  r.is_active = TRUE
  AND  NOT EXISTS (
           SELECT 1
           FROM   PolicyRole pr
           WHERE  pr.role_id = r.role_id
       )
ORDER  BY r.is_privileged DESC, r.role_name;


-- ─────────────────────────────────────────────
-- Q11: AUDIT LOG ACTIVITY SUMMARY per user (last 30 days)
-- Technique: Aggregation + HAVING + window function
-- ─────────────────────────────────────────────
SELECT u.username,
       al.action,
       al.table_name,
       COUNT(*)                                   AS action_count,
       MAX(al.performed_at)                       AS last_performed,
       RANK() OVER (PARTITION BY al.action
                    ORDER BY COUNT(*) DESC)        AS rank_within_action
FROM   AuditLogs al
JOIN   Users     u ON u.user_id = al.user_id
WHERE  al.performed_at >= NOW() - INTERVAL '30 days'
GROUP  BY u.username, al.action, al.table_name
ORDER  BY action_count DESC;


-- ─────────────────────────────────────────────
-- Q12: MULTI-ROLE USERS with conflicting permission sensitivity
-- Users where one role gives Public access and another gives Highly Confidential
-- Technique: Self-join + correlated subquery + 4 tables
-- ─────────────────────────────────────────────
SELECT DISTINCT u.username,
       r1.role_name AS low_sensitivity_role,
       r2.role_name AS high_sensitivity_role,
       p1.permission_name AS low_perm,
       p2.permission_name AS high_perm
FROM   Users          u
JOIN   UserRole       ur1 ON ur1.user_id = u.user_id AND ur1.is_active = TRUE
JOIN   Roles          r1  ON r1.role_id  = ur1.role_id
JOIN   RolePermission rp1 ON rp1.role_id = r1.role_id AND rp1.is_active = TRUE
JOIN   Permissions    p1  ON p1.permission_id = rp1.permission_id
                          AND p1.data_sensitivity = 'Public'
JOIN   UserRole       ur2 ON ur2.user_id = u.user_id AND ur2.is_active = TRUE
JOIN   Roles          r2  ON r2.role_id  = ur2.role_id
JOIN   RolePermission rp2 ON rp2.role_id = r2.role_id AND rp2.is_active = TRUE
JOIN   Permissions    p2  ON p2.permission_id = rp2.permission_id
                          AND p2.data_sensitivity = 'Highly Confidential'
WHERE  r1.role_id <> r2.role_id
ORDER  BY u.username;


-- ─────────────────────────────────────────────
-- Q13: ORPHANED USERS — active users with NO active role assignment
-- Technique: Anti-join (NOT EXISTS)
-- ─────────────────────────────────────────────
SELECT u.user_id,
       u.username,
       u.email,
       u.auth_mechanism,
       u.is_active,
       u.account_locked
FROM   Users u
WHERE  u.is_active = TRUE
  AND  NOT EXISTS (
           SELECT 1
           FROM   UserRole ur
           WHERE  ur.user_id  = u.user_id
             AND  ur.is_active = TRUE
       )
ORDER  BY u.username;


-- ─────────────────────────────────────────────
-- Q14: ORPHANED ROLES — roles with NO users assigned
-- Technique: Anti-join (NOT EXISTS)
-- ─────────────────────────────────────────────
SELECT r.role_id,
       r.role_name,
       r.auth_model,
       r.is_privileged,
       r.is_active
FROM   Roles r
WHERE  NOT EXISTS (
           SELECT 1
           FROM   UserRole ur
           WHERE  ur.role_id  = r.role_id
             AND  ur.is_active = TRUE
       )
ORDER  BY r.role_name;


-- ─────────────────────────────────────────────
-- Q15: COMPLIANCE COVERAGE — permissions by compliance tag per role
-- Roles that hold GDPR-tagged permissions but lack MFA enforcement
-- Technique: Nested subquery + aggregation + HAVING
-- ─────────────────────────────────────────────
SELECT r.role_name,
       pol.compliance_tag,
       COUNT(DISTINCT p.permission_id) AS gdpr_permissions,
       BOOL_OR(p.requires_mfa)         AS any_mfa_required,
       BOOL_AND(pol.mfa_required)      AS policy_mfa_required
FROM   Roles          r
JOIN   RolePermission rp  ON rp.role_id      = r.role_id AND rp.is_active = TRUE
JOIN   Permissions    p   ON p.permission_id  = rp.permission_id
                          AND p.compliance_tag IS NOT NULL
JOIN   PolicyRole     pr  ON pr.role_id      = r.role_id
JOIN   Policies       pol ON pol.policy_id   = pr.policy_id AND pol.is_active = TRUE
GROUP  BY r.role_name, pol.compliance_tag
HAVING COUNT(DISTINCT p.permission_id) > 0
ORDER  BY gdpr_permissions DESC;


-- ─────────────────────────────────────────────
-- Q16: SESSION ANOMALY — users with active sessions in unusual geolocations
-- Compared to their registered geolocation
-- Technique: Correlated subquery + CASE
-- ─────────────────────────────────────────────
SELECT u.username,
       u.geolocation            AS registered_location,
       s.geolocation            AS session_location,
       s.ip_address,
       s.auth_mechanism,
       s.started_at,
       CASE
           WHEN u.geolocation IS NULL THEN 'NO_REG_GEO'
           WHEN s.geolocation IS NULL THEN 'NO_SESSION_GEO'
           WHEN u.geolocation <> s.geolocation THEN 'MISMATCH'
           ELSE 'OK'
       END AS geo_status
FROM   Sessions s
JOIN   Users    u ON u.user_id = s.user_id
WHERE  s.is_active = TRUE
  AND  (
           u.geolocation IS NULL
        OR s.geolocation IS NULL
        OR u.geolocation <> s.geolocation
       )
ORDER  BY s.started_at DESC;


-- ─────────────────────────────────────────────
-- Q17: ROLE PERMISSION COUNT with running total (window)
-- Technique: Window function (SUM OVER), 2-table join
-- ─────────────────────────────────────────────
SELECT r.role_name,
       r.auth_model,
       r.is_privileged,
       COUNT(rp.permission_id)                             AS permission_count,
       SUM(COUNT(rp.permission_id))
           OVER (ORDER BY COUNT(rp.permission_id) DESC
                 ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)
                                                           AS running_total
FROM   Roles          r
LEFT JOIN RolePermission rp ON rp.role_id = r.role_id AND rp.is_active = TRUE
WHERE  r.is_active = TRUE
GROUP  BY r.role_name, r.auth_model, r.is_privileged
ORDER  BY permission_count DESC;


-- ─────────────────────────────────────────────
-- Q18: LOCKED / HIGH-RISK ACCOUNTS with their roles and last activity
-- Technique: Multi-join (4 tables) + subquery for last activity
-- ─────────────────────────────────────────────
SELECT u.username,
       u.account_locked,
       u.failed_login_count,
       u.auth_mechanism,
       STRING_AGG(DISTINCT r.role_name, ', ') AS roles,
       (
           SELECT MAX(al.performed_at)
           FROM   AuditLogs al
           WHERE  al.user_id = u.user_id
       )                                       AS last_activity
FROM   Users u
LEFT JOIN UserRole ur ON ur.user_id = u.user_id AND ur.is_active = TRUE
LEFT JOIN Roles    r  ON r.role_id  = ur.role_id
WHERE  u.account_locked = TRUE OR u.failed_login_count >= 3
GROUP  BY u.user_id, u.username, u.account_locked,
          u.failed_login_count, u.auth_mechanism
ORDER  BY u.failed_login_count DESC;


-- ─────────────────────────────────────────────
-- Q19: PERMISSION INHERITANCE vs DIRECT GRANT comparison
-- How many permissions come from hierarchy vs direct role
-- Technique: Two CTEs (direct vs inherited), window function
-- ─────────────────────────────────────────────
WITH RECURSIVE direct_perms AS (
    SELECT ur.user_id, COUNT(DISTINCT rp.permission_id) AS direct_count
    FROM   UserRole       ur
    JOIN   RolePermission rp ON rp.role_id = ur.role_id AND rp.is_active = TRUE
    WHERE  ur.is_active = TRUE
    GROUP  BY ur.user_id
),
rt AS (
    SELECT ur.user_id, ur.role_id, 0 AS d
    FROM   UserRole ur WHERE ur.is_active = TRUE
    UNION ALL
    SELECT rt.user_id, rh.parent_role, rt.d + 1
    FROM   rt JOIN RoleHierarchy rh ON rh.child_role = rt.role_id
    WHERE  rt.d < 10
),
inherited_perms AS (
    SELECT rt.user_id, COUNT(DISTINCT rp.permission_id) AS inherited_count
    FROM   rt
    JOIN   RolePermission rp ON rp.role_id = rt.role_id AND rp.is_active = TRUE
    WHERE  rt.d > 0
    GROUP  BY rt.user_id
)
SELECT u.username,
       COALESCE(dp.direct_count,    0) AS direct_perms,
       COALESCE(ip.inherited_count, 0) AS inherited_perms,
       COALESCE(dp.direct_count,    0)
     + COALESCE(ip.inherited_count, 0) AS total_perms,
       DENSE_RANK() OVER (ORDER BY
           COALESCE(dp.direct_count, 0)
         + COALESCE(ip.inherited_count, 0) DESC) AS overall_rank
FROM   Users u
LEFT JOIN direct_perms    dp ON dp.user_id = u.user_id
LEFT JOIN inherited_perms ip ON ip.user_id = u.user_id
WHERE  u.is_active = TRUE
ORDER  BY total_perms DESC;


-- ─────────────────────────────────────────────
-- Q20: API PERMISSION EXPOSURE — users who can call sensitive APIs without MFA
-- Technique: 4-table join + nested subquery
-- ─────────────────────────────────────────────
SELECT u.username,
       u.auth_mechanism,
       r.role_name,
       p.permission_name,
       p.resource,
       p.data_sensitivity
FROM   Users          u
JOIN   UserRole       ur ON ur.user_id      = u.user_id AND ur.is_active = TRUE
JOIN   Roles          r  ON r.role_id       = ur.role_id
JOIN   RolePermission rp ON rp.role_id      = r.role_id AND rp.is_active = TRUE
JOIN   Permissions    p  ON p.permission_id = rp.permission_id
WHERE  p.api_permission = TRUE
  AND  p.requires_mfa   = TRUE
  AND  u.auth_mechanism IN ('Password', 'SSO')
  AND  p.data_sensitivity IN ('Confidential', 'Highly Confidential')
ORDER  BY p.data_sensitivity DESC, u.username;


-- ─────────────────────────────────────────────
-- Q21: POLICY COMPLIANCE per role (score distribution)
-- Average security score by auth model + privileged status
-- Technique: Aggregation, HAVING, ROLLUP
-- ─────────────────────────────────────────────
SELECT r.auth_model,
       r.is_privileged,
       COUNT(DISTINCT r.role_id)       AS role_count,
       ROUND(AVG(pol.security_score), 2) AS avg_security_score,
       MIN(pol.security_score)          AS min_score,
       MAX(pol.security_score)          AS max_score
FROM   Roles      r
JOIN   PolicyRole pr  ON pr.role_id  = r.role_id
JOIN   Policies   pol ON pol.policy_id = pr.policy_id AND pol.is_active = TRUE
WHERE  r.is_active = TRUE
GROUP  BY r.auth_model, r.is_privileged
HAVING COUNT(DISTINCT r.role_id) > 0
ORDER  BY r.auth_model NULLS LAST, r.is_privileged NULLS LAST;


-- ─────────────────────────────────────────────
-- Q22: TOP-N MOST ACCESSED RESOURCES (by number of roles granting access)
-- Technique: Aggregation + window function NTILE
-- ─────────────────────────────────────────────
SELECT p.resource,
       p.access_level,
       p.data_sensitivity,
       COUNT(DISTINCT rp.role_id) AS roles_granting_access,
       NTILE(4) OVER (ORDER BY COUNT(DISTINCT rp.role_id) DESC) AS quartile
FROM   Permissions    p
JOIN   RolePermission rp ON rp.permission_id = p.permission_id AND rp.is_active = TRUE
WHERE  p.is_active = TRUE
GROUP  BY p.resource, p.access_level, p.data_sensitivity
ORDER  BY roles_granting_access DESC;


-- ─────────────────────────────────────────────
-- Q23: SEGREGATION OF DUTIES VIOLATION
-- Users who have BOTH finance permissions AND IAM permissions (SOD conflict)
-- Technique: Correlated EXISTS subqueries + 3-table join
-- ─────────────────────────────────────────────
SELECT u.username,
       u.email,
       STRING_AGG(DISTINCT r.role_name, ', ') AS roles
FROM   Users          u
JOIN   UserRole       ur ON ur.user_id = u.user_id AND ur.is_active = TRUE
JOIN   Roles          r  ON r.role_id  = ur.role_id
WHERE  EXISTS (
    -- Has a finance permission
    SELECT 1
    FROM   UserRole       ur2
    JOIN   RolePermission rp2 ON rp2.role_id = ur2.role_id AND rp2.is_active = TRUE
    JOIN   Permissions    p2  ON p2.permission_id = rp2.permission_id
    WHERE  ur2.user_id = u.user_id
      AND  ur2.is_active = TRUE
      AND  p2.resource LIKE 'finance%'
)
AND EXISTS (
    -- Also has an IAM permission
    SELECT 1
    FROM   UserRole       ur3
    JOIN   RolePermission rp3 ON rp3.role_id = ur3.role_id AND rp3.is_active = TRUE
    JOIN   Permissions    p3  ON p3.permission_id = rp3.permission_id
    WHERE  ur3.user_id = u.user_id
      AND  ur3.is_active = TRUE
      AND  p3.resource LIKE 'iam%'
)
GROUP  BY u.user_id, u.username, u.email
ORDER  BY u.username;


-- ─────────────────────────────────────────────
-- Q24: PENDING PRIVILEGE REQUESTS with risk assessment
-- Score = (is_privileged * 3) + (data_sensitivity weight)
-- Technique: CASE scoring, 4-table join, subquery
-- ─────────────────────────────────────────────
SELECT pr.request_id,
       u.username        AS requestor,
       r.role_name       AS requested_role,
       r.is_privileged,
       pr.justification,
       pr.requested_at,
       (
           SELECT COUNT(*)
           FROM   RolePermission rp2
           JOIN   Permissions    p2 ON p2.permission_id = rp2.permission_id
           WHERE  rp2.role_id = r.role_id
             AND  p2.data_sensitivity IN ('Confidential','Highly Confidential')
       )                 AS sensitive_perm_count,
       CASE r.is_privileged WHEN TRUE THEN 3 ELSE 1 END
     + COALESCE((
           SELECT SUM(
               CASE p3.data_sensitivity
                   WHEN 'Highly Confidential' THEN 3
                   WHEN 'Confidential'         THEN 2
                   WHEN 'Private'              THEN 1
                   ELSE 0
               END)
           FROM   RolePermission rp3
           JOIN   Permissions    p3 ON p3.permission_id = rp3.permission_id
           WHERE  rp3.role_id = r.role_id AND rp3.is_active = TRUE
       ), 0)             AS risk_score
FROM   PrivilegeRequests pr
JOIN   Users u ON u.user_id = pr.requestor_id
JOIN   Roles r ON r.role_id = pr.target_role_id
WHERE  pr.status = 'PENDING'
ORDER  BY risk_score DESC;


-- ─────────────────────────────────────────────
-- Q25: FULL ACCESS CONTROL HEALTH DASHBOARD
-- Per-user summary: roles, perms, policy count, session status, risk flag
-- Technique: Multiple CTEs + window functions + multi-table join (7 tables)
-- ─────────────────────────────────────────────
WITH role_summary AS (
    SELECT ur.user_id,
           COUNT(DISTINCT ur.role_id)              AS role_count,
           BOOL_OR(r.is_privileged)                AS has_privileged_role
    FROM   UserRole ur
    JOIN   Roles    r ON r.role_id = ur.role_id
    WHERE  ur.is_active = TRUE
    GROUP  BY ur.user_id
),
perm_summary AS (
    SELECT ur.user_id,
           COUNT(DISTINCT rp.permission_id)        AS perm_count,
           BOOL_OR(p.requires_mfa)                 AS any_requires_mfa
    FROM   UserRole       ur
    JOIN   RolePermission rp ON rp.role_id = ur.role_id AND rp.is_active = TRUE
    JOIN   Permissions    p  ON p.permission_id = rp.permission_id
    WHERE  ur.is_active = TRUE
    GROUP  BY ur.user_id
),
policy_summary AS (
    SELECT ur.user_id,
           COUNT(DISTINCT pr.policy_id)            AS policy_count,
           BOOL_OR(pol.zero_trust)                 AS has_zero_trust_policy
    FROM   UserRole   ur
    JOIN   PolicyRole pr  ON pr.role_id   = ur.role_id
    JOIN   Policies   pol ON pol.policy_id = pr.policy_id AND pol.is_active = TRUE
    WHERE  ur.is_active = TRUE
    GROUP  BY ur.user_id
),
session_summary AS (
    SELECT user_id,
           COUNT(*)                                AS total_sessions,
           SUM(CASE WHEN is_active THEN 1 ELSE 0 END) AS active_sessions
    FROM   Sessions
    GROUP  BY user_id
)
SELECT u.username,
       u.auth_mechanism,
       u.account_locked,
       COALESCE(rs.role_count,   0)                AS roles,
       COALESCE(ps.perm_count,   0)                AS permissions,
       COALESCE(plc.policy_count,0)                AS policies,
       COALESCE(ss.active_sessions, 0)             AS active_sessions,
       rs.has_privileged_role,
       ps.any_requires_mfa,
       plc.has_zero_trust_policy,
       CASE
           WHEN u.account_locked                           THEN 'LOCKED'
           WHEN rs.has_privileged_role
                AND u.auth_mechanism = 'Password'         THEN 'HIGH_RISK'
           WHEN ps.any_requires_mfa
                AND u.auth_mechanism IN ('Password','SSO') THEN 'MEDIUM_RISK'
           ELSE 'OK'
       END                                          AS risk_status,
       RANK() OVER (ORDER BY COALESCE(ps.perm_count, 0) DESC) AS perm_rank
FROM   Users           u
LEFT JOIN role_summary    rs  ON rs.user_id  = u.user_id
LEFT JOIN perm_summary    ps  ON ps.user_id  = u.user_id
LEFT JOIN policy_summary  plc ON plc.user_id = u.user_id
LEFT JOIN session_summary ss  ON ss.user_id  = u.user_id
WHERE  u.is_active = TRUE
ORDER  BY risk_status, perm_rank;


-- ════════════════════════════════════════════════
-- SECTION B: DISJOINT (SET-BASED) QUERIES (D1–D10)
-- ════════════════════════════════════════════════

-- ─────────────────────────────────────────────
-- D1: UNION — All users who are either Admins OR SuperAdmins
-- ─────────────────────────────────────────────
SELECT u.username, 'Admin'      AS assignment_type, r.role_name
FROM   Users u
JOIN   UserRole ur ON ur.user_id = u.user_id AND ur.is_active = TRUE
JOIN   Roles    r  ON r.role_id  = ur.role_id AND r.role_name = 'Admin'

UNION

SELECT u.username, 'SuperAdmin' AS assignment_type, r.role_name
FROM   Users u
JOIN   UserRole ur ON ur.user_id = u.user_id AND ur.is_active = TRUE
JOIN   Roles    r  ON r.role_id  = ur.role_id AND r.role_name = 'SuperAdmin'

ORDER  BY assignment_type, username;


-- ─────────────────────────────────────────────
-- D2: EXCEPT — Users with Developer role but NOT Guest role
-- ─────────────────────────────────────────────
SELECT u.username
FROM   Users    u
JOIN   UserRole ur ON ur.user_id = u.user_id AND ur.is_active = TRUE
JOIN   Roles    r  ON r.role_id  = ur.role_id AND r.role_name = 'Developer'

EXCEPT

SELECT u.username
FROM   Users    u
JOIN   UserRole ur ON ur.user_id = u.user_id AND ur.is_active = TRUE
JOIN   Roles    r  ON r.role_id  = ur.role_id AND r.role_name = 'Guest'

ORDER  BY username;


-- ─────────────────────────────────────────────
-- D3: INTERSECT — Permissions common to both Admin and Developer roles
-- ─────────────────────────────────────────────
SELECT p.permission_name, p.resource, p.access_level
FROM   Permissions    p
JOIN   RolePermission rp ON rp.permission_id = p.permission_id AND rp.is_active = TRUE
JOIN   Roles          r  ON r.role_id = rp.role_id AND r.role_name = 'Admin'

INTERSECT

SELECT p.permission_name, p.resource, p.access_level
FROM   Permissions    p
JOIN   RolePermission rp ON rp.permission_id = p.permission_id AND rp.is_active = TRUE
JOIN   Roles          r  ON r.role_id = rp.role_id AND r.role_name = 'Developer'

ORDER  BY permission_name;


-- ─────────────────────────────────────────────
-- D4: EXCEPT — Permissions exclusive to SuperAdmin (not in Admin)
-- ─────────────────────────────────────────────
SELECT p.permission_name, p.resource, p.access_level
FROM   Permissions    p
JOIN   RolePermission rp ON rp.permission_id = p.permission_id AND rp.is_active = TRUE
JOIN   Roles          r  ON r.role_id = rp.role_id AND r.role_name = 'SuperAdmin'

EXCEPT

SELECT p.permission_name, p.resource, p.access_level
FROM   Permissions    p
JOIN   RolePermission rp ON rp.permission_id = p.permission_id AND rp.is_active = TRUE
JOIN   Roles          r  ON r.role_id = rp.role_id AND r.role_name = 'Admin'

ORDER  BY permission_name;


-- ─────────────────────────────────────────────
-- D5: UNION ALL — All role assignment events (INSERT + approved escalations)
-- ─────────────────────────────────────────────
SELECT u.username, r.role_name, 'DIRECT_ASSIGNMENT' AS source, ur.assigned_at AS event_time
FROM   UserRole ur
JOIN   Users u ON u.user_id = ur.user_id
JOIN   Roles  r ON r.role_id = ur.role_id

UNION ALL

SELECT u.username, r.role_name, 'ESCALATION_APPROVED' AS source, pr.reviewed_at AS event_time
FROM   PrivilegeRequests pr
JOIN   Users u ON u.user_id = pr.requestor_id
JOIN   Roles  r ON r.role_id = pr.target_role_id
WHERE  pr.status = 'APPROVED'

ORDER  BY event_time DESC NULLS LAST;


-- ─────────────────────────────────────────────
-- D6: INTERSECT — Users who have active sessions AND active role assignments
-- (confirmed authenticated + authorized simultaneously)
-- ─────────────────────────────────────────────
SELECT u.username
FROM   Users    u
JOIN   Sessions s  ON s.user_id = u.user_id AND s.is_active = TRUE

INTERSECT

SELECT u.username
FROM   Users    u
JOIN   UserRole ur ON ur.user_id = u.user_id AND ur.is_active = TRUE

ORDER  BY username;


-- ─────────────────────────────────────────────
-- D7: EXCEPT — Roles that have permissions but are NOT covered by any policy
-- ─────────────────────────────────────────────
SELECT DISTINCT r.role_name
FROM   Roles          r
JOIN   RolePermission rp ON rp.role_id = r.role_id AND rp.is_active = TRUE

EXCEPT

SELECT DISTINCT r.role_name
FROM   Roles      r
JOIN   PolicyRole pr ON pr.role_id = r.role_id

ORDER  BY role_name;


-- ─────────────────────────────────────────────
-- D8: UNION — Resources accessible via either MFA or Biometric authentication
-- ─────────────────────────────────────────────
SELECT DISTINCT p.resource, 'MFA' AS auth_type
FROM   Permissions p
JOIN   RolePermission rp ON rp.permission_id = p.permission_id AND rp.is_active = TRUE
JOIN   Roles          r  ON r.role_id = rp.role_id
JOIN   UserRole       ur ON ur.role_id = r.role_id AND ur.is_active = TRUE
JOIN   Users          u  ON u.user_id  = ur.user_id AND u.auth_mechanism = 'MFA'

UNION

SELECT DISTINCT p.resource, 'Biometric' AS auth_type
FROM   Permissions p
JOIN   RolePermission rp ON rp.permission_id = p.permission_id AND rp.is_active = TRUE
JOIN   Roles          r  ON r.role_id = rp.role_id
JOIN   UserRole       ur ON ur.role_id = r.role_id AND ur.is_active = TRUE
JOIN   Users          u  ON u.user_id  = ur.user_id AND u.auth_mechanism = 'Biometric'

ORDER  BY resource, auth_type;


-- ─────────────────────────────────────────────
-- D9: EXCEPT — Compliance-tagged permissions not assigned to any active role
-- (compliance gap — permissions defined but unattached)
-- ─────────────────────────────────────────────
SELECT p.permission_name, p.compliance_tag, p.resource
FROM   Permissions p
WHERE  p.compliance_tag IS NOT NULL
  AND  p.is_active = TRUE

EXCEPT

SELECT p.permission_name, p.compliance_tag, p.resource
FROM   Permissions    p
JOIN   RolePermission rp ON rp.permission_id = p.permission_id AND rp.is_active = TRUE

ORDER  BY compliance_tag, permission_name;


-- ─────────────────────────────────────────────
-- D10: UNION ALL — Complete audit trail: role assignments + privilege escalations + session starts
-- Full unified timeline for a security review
-- ─────────────────────────────────────────────
SELECT 'ROLE_ASSIGNED'   AS event_type,
       u.username,
       r.role_name        AS context,
       ur.assigned_at     AS event_time
FROM   UserRole ur
JOIN   Users u ON u.user_id = ur.user_id
JOIN   Roles  r ON r.role_id = ur.role_id

UNION ALL

SELECT 'PRIV_REQUEST_'|| pr.status AS event_type,
       u.username,
       r.role_name                  AS context,
       COALESCE(pr.reviewed_at, pr.requested_at) AS event_time
FROM   PrivilegeRequests pr
JOIN   Users u ON u.user_id = pr.requestor_id
JOIN   Roles  r ON r.role_id = pr.target_role_id

UNION ALL

SELECT 'SESSION_STARTED' AS event_type,
       u.username,
       s.geolocation || ' via ' || s.auth_mechanism::TEXT AS context,
       s.started_at      AS event_time
FROM   Sessions s
JOIN   Users u ON u.user_id = s.user_id

ORDER  BY event_time DESC NULLS LAST
LIMIT  100;
