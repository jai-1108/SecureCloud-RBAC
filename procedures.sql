-- ============================================================
-- RBAC System — procedures.sql
-- Stored Procedures (PostgreSQL PL/pgSQL)
-- ============================================================

-- ─────────────────────────────────────────────
-- SP1: GetUserPermissions(p_user_id INT)
-- Returns all effective permissions for a user (with hierarchy)
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION GetUserPermissions(p_user_id INT)
RETURNS TABLE (
    role_name        VARCHAR,
    inheritance_depth INT,
    permission_name  VARCHAR,
    resource         VARCHAR,
    access_level     access_level,
    data_sensitivity data_sensitivity,
    requires_mfa     BOOLEAN,
    compliance_tag   VARCHAR,
    api_permission   BOOLEAN
)
LANGUAGE plpgsql
AS $$
BEGIN
    -- Validate user exists
    IF NOT EXISTS (SELECT 1 FROM Users WHERE user_id = p_user_id) THEN
        RAISE EXCEPTION 'User % not found', p_user_id;
    END IF;

    RETURN QUERY
    WITH RECURSIVE role_tree AS (
        SELECT ur.role_id, 0 AS depth
        FROM   UserRole ur
        WHERE  ur.user_id   = p_user_id
          AND  ur.is_active = TRUE

        UNION ALL

        SELECT rh.parent_role, rt.depth + 1
        FROM   role_tree     rt
        JOIN   RoleHierarchy rh ON rh.child_role = rt.role_id
        WHERE  rt.depth < 10
    )
    SELECT DISTINCT
        r.role_name::VARCHAR,
        rt.depth,
        p.permission_name::VARCHAR,
        p.resource::VARCHAR,
        p.access_level,
        p.data_sensitivity,
        p.requires_mfa,
        p.compliance_tag::VARCHAR,
        p.api_permission
    FROM   role_tree      rt
    JOIN   Roles          r  ON r.role_id       = rt.role_id
    JOIN   RolePermission rp ON rp.role_id      = rt.role_id AND rp.is_active = TRUE
    JOIN   Permissions    p  ON p.permission_id = rp.permission_id AND p.is_active = TRUE
    ORDER  BY rt.depth, p.permission_name;
END;
$$;


-- ─────────────────────────────────────────────
-- SP2: AssignRole(p_user_id INT, p_role_id INT, p_assigned_by INT)
-- Assigns a role to a user; raises error on invalid state
-- Inserts an audit log entry automatically
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION AssignRole(
    p_user_id     INT,
    p_role_id     INT,
    p_assigned_by INT DEFAULT NULL
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_existing INT;
    v_role_name VARCHAR;
    v_username  VARCHAR;
BEGIN
    -- Validate user
    SELECT username INTO v_username FROM Users WHERE user_id = p_user_id AND is_active = TRUE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'User % not found or inactive', p_user_id;
    END IF;

    -- Check account not locked
    IF EXISTS (SELECT 1 FROM Users WHERE user_id = p_user_id AND account_locked = TRUE) THEN
        RAISE EXCEPTION 'Cannot assign role: account % is locked', v_username;
    END IF;

    -- Validate role
    SELECT role_name INTO v_role_name FROM Roles WHERE role_id = p_role_id AND is_active = TRUE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role % not found or inactive', p_role_id;
    END IF;

    -- Check for existing active assignment
    SELECT user_role_id INTO v_existing
    FROM   UserRole
    WHERE  user_id = p_user_id AND role_id = p_role_id AND is_active = TRUE;

    IF FOUND THEN
        RETURN FORMAT('Role "%s" already assigned to user "%s"', v_role_name, v_username);
    END IF;

    -- Insert assignment
    INSERT INTO UserRole (user_id, role_id, assigned_by, is_active)
    VALUES (p_user_id, p_role_id, p_assigned_by, TRUE);

    -- Trigger trg_userrole_audit handles the audit log automatically.

    RETURN FORMAT('Role "%s" successfully assigned to user "%s"', v_role_name, v_username);
END;
$$;


-- ─────────────────────────────────────────────
-- SP3: RevokeRole(p_user_id INT, p_role_id INT, p_revoked_by INT)
-- Deactivates a role assignment and logs the revocation
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION RevokeRole(
    p_user_id    INT,
    p_role_id    INT,
    p_revoked_by INT DEFAULT NULL
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_role_name VARCHAR;
    v_username  VARCHAR;
    v_rows      INT;
BEGIN
    SELECT username  INTO v_username  FROM Users WHERE user_id = p_user_id;
    SELECT role_name INTO v_role_name FROM Roles WHERE role_id = p_role_id;

    UPDATE UserRole
    SET    is_active = FALSE
    WHERE  user_id = p_user_id AND role_id = p_role_id AND is_active = TRUE;

    GET DIAGNOSTICS v_rows = ROW_COUNT;

    IF v_rows = 0 THEN
        RETURN FORMAT('No active assignment found for user "%s" with role "%s"',
                      v_username, v_role_name);
    END IF;

    -- Trigger trg_userrole_audit handles the audit log automatically.

    RETURN FORMAT('Role "%s" revoked from user "%s"', v_role_name, v_username);
END;
$$;


-- ─────────────────────────────────────────────
-- SP4: GetRoleHierarchy(p_role_id INT)
-- Returns the full hierarchy chain for a given role
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION GetRoleHierarchy(p_role_id INT)
RETURNS TABLE (
    role_name     VARCHAR,
    parent_name   VARCHAR,
    level         INT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE hierarchy AS (
        SELECT r.role_id, r.role_name::VARCHAR, NULL::VARCHAR AS parent_name, 0 AS lvl
        FROM   Roles r WHERE r.role_id = p_role_id

        UNION ALL

        SELECT r.role_id, r.role_name::VARCHAR, h.role_name AS parent_name, h.lvl + 1
        FROM   hierarchy     h
        JOIN   RoleHierarchy rh ON rh.child_role  = h.role_id
        JOIN   Roles          r ON r.role_id      = rh.parent_role
        WHERE  h.lvl < 15
    )
    SELECT role_name, parent_name, lvl FROM hierarchy ORDER BY lvl;
END;
$$;


-- ─────────────────────────────────────────────
-- SP5: DetectPrivilegeEscalation()
-- Returns users with more permissions than their roles should grant
-- (has privileged permission without privileged role flag)
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION DetectPrivilegeEscalation()
RETURNS TABLE (
    username          VARCHAR,
    role_name         VARCHAR,
    is_privileged     BOOLEAN,
    permission_name   VARCHAR,
    access_level      access_level,
    data_sensitivity  data_sensitivity
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT e.username::VARCHAR,
           e.role_name::VARCHAR,
           e.role_is_privileged AS is_privileged,
           e.permission_name::VARCHAR,
           e.access_level,
           e.data_sensitivity
    FROM   EffectivePermissionsView e
    WHERE  e.role_is_privileged = FALSE
      AND  e.access_level = 'Admin'
      AND  e.data_sensitivity IN ('Confidential','Highly Confidential')
    ORDER  BY e.username, e.data_sensitivity DESC;
END;
$$;
