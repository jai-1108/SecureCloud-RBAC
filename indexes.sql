-- ============================================================
-- RBAC System — indexes.sql
-- Optimized indexes for join columns and query patterns
-- ============================================================

-- ─────────────────────────────────────────────
-- USERS
-- ─────────────────────────────────────────────
CREATE INDEX idx_users_username        ON Users(username);
CREATE INDEX idx_users_email           ON Users(email);
CREATE INDEX idx_users_is_active       ON Users(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_users_account_locked  ON Users(account_locked) WHERE account_locked = TRUE;
CREATE INDEX idx_users_auth_mechanism  ON Users(auth_mechanism);
CREATE INDEX idx_users_cloud_provider  ON Users(cloud_provider);
CREATE INDEX idx_users_geolocation     ON Users(geolocation);

-- ─────────────────────────────────────────────
-- ROLES
-- ─────────────────────────────────────────────
CREATE INDEX idx_roles_role_name       ON Roles(role_name);
CREATE INDEX idx_roles_is_active       ON Roles(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_roles_is_privileged   ON Roles(is_privileged);
CREATE INDEX idx_roles_auth_model      ON Roles(auth_model);

-- ─────────────────────────────────────────────
-- USER ROLE  (most heavily queried join table)
-- ─────────────────────────────────────────────
CREATE INDEX idx_userrole_user_id      ON UserRole(user_id);
CREATE INDEX idx_userrole_role_id      ON UserRole(role_id);
CREATE INDEX idx_userrole_active       ON UserRole(user_id, role_id) WHERE is_active = TRUE;
CREATE INDEX idx_userrole_expires      ON UserRole(expires_at) WHERE expires_at IS NOT NULL;

-- ─────────────────────────────────────────────
-- ROLE PERMISSION
-- ─────────────────────────────────────────────
CREATE INDEX idx_roleperm_role_id      ON RolePermission(role_id);
CREATE INDEX idx_roleperm_perm_id      ON RolePermission(permission_id);
CREATE INDEX idx_roleperm_active       ON RolePermission(role_id, permission_id) WHERE is_active = TRUE;

-- ─────────────────────────────────────────────
-- PERMISSIONS
-- ─────────────────────────────────────────────
CREATE INDEX idx_perm_resource         ON Permissions(resource);
CREATE INDEX idx_perm_access_level     ON Permissions(access_level);
CREATE INDEX idx_perm_data_sensitivity ON Permissions(data_sensitivity);
CREATE INDEX idx_perm_requires_mfa     ON Permissions(requires_mfa) WHERE requires_mfa = TRUE;
CREATE INDEX idx_perm_compliance_tag   ON Permissions(compliance_tag);
CREATE INDEX idx_perm_api_permission   ON Permissions(api_permission) WHERE api_permission = TRUE;
CREATE INDEX idx_perm_active           ON Permissions(permission_id) WHERE is_active = TRUE;

-- ─────────────────────────────────────────────
-- ROLE HIERARCHY  (critical for recursive CTE performance)
-- ─────────────────────────────────────────────
CREATE INDEX idx_rolehier_parent       ON RoleHierarchy(parent_role);
CREATE INDEX idx_rolehier_child        ON RoleHierarchy(child_role);
CREATE INDEX idx_rolehier_both         ON RoleHierarchy(parent_role, child_role);

-- ─────────────────────────────────────────────
-- SESSIONS
-- ─────────────────────────────────────────────
CREATE INDEX idx_sessions_user_id      ON Sessions(user_id);
CREATE INDEX idx_sessions_is_active    ON Sessions(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_sessions_started_at   ON Sessions(started_at DESC);
CREATE INDEX idx_sessions_expires_at   ON Sessions(expires_at);
CREATE INDEX idx_sessions_geolocation  ON Sessions(geolocation);
CREATE INDEX idx_sessions_token        ON Sessions(session_token);

-- ─────────────────────────────────────────────
-- AUDIT LOGS  (time-series, typically large)
-- ─────────────────────────────────────────────
CREATE INDEX idx_audit_user_id         ON AuditLogs(user_id);
CREATE INDEX idx_audit_role_id         ON AuditLogs(role_id);
CREATE INDEX idx_audit_table_name      ON AuditLogs(table_name);
CREATE INDEX idx_audit_performed_at    ON AuditLogs(performed_at DESC);
CREATE INDEX idx_audit_action          ON AuditLogs(action);
-- Composite for dashboard query
CREATE INDEX idx_audit_user_time       ON AuditLogs(user_id, performed_at DESC);

-- ─────────────────────────────────────────────
-- POLICIES
-- ─────────────────────────────────────────────
CREATE INDEX idx_policies_active       ON Policies(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_policies_compliance   ON Policies(compliance_tag);
CREATE INDEX idx_policies_auth_model   ON Policies(auth_model);
CREATE INDEX idx_policies_sec_score    ON Policies(security_score);

-- ─────────────────────────────────────────────
-- POLICY ROLE
-- ─────────────────────────────────────────────
CREATE INDEX idx_policyrole_policy_id  ON PolicyRole(policy_id);
CREATE INDEX idx_policyrole_role_id    ON PolicyRole(role_id);

-- ─────────────────────────────────────────────
-- PRIVILEGE REQUESTS
-- ─────────────────────────────────────────────
CREATE INDEX idx_privreq_requestor     ON PrivilegeRequests(requestor_id);
CREATE INDEX idx_privreq_target_role   ON PrivilegeRequests(target_role_id);
CREATE INDEX idx_privreq_status        ON PrivilegeRequests(status);
CREATE INDEX idx_privreq_requested_at  ON PrivilegeRequests(requested_at DESC);
