-- ============================================================
-- RBAC System — triggers.sql
-- Audit triggers for critical tables
-- ============================================================

-- ─────────────────────────────────────────────
-- Helper: Generic audit function used by all triggers
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION fn_audit_log()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_action     action_type;
    v_old_values JSONB := NULL;
    v_new_values JSONB := NULL;
    v_record_id  INT   := NULL;
BEGIN
    v_action := TG_OP::action_type;

    IF TG_OP = 'INSERT' THEN
        v_new_values := to_jsonb(NEW);
        -- Extract PK dynamically
        BEGIN v_record_id := (v_new_values->>(LOWER(TG_TABLE_NAME)||'_id'))::INT; EXCEPTION WHEN OTHERS THEN NULL; END;
    ELSIF TG_OP = 'UPDATE' THEN
        v_old_values := to_jsonb(OLD);
        v_new_values := to_jsonb(NEW);
        BEGIN v_record_id := (v_new_values->>(LOWER(TG_TABLE_NAME)||'_id'))::INT; EXCEPTION WHEN OTHERS THEN NULL; END;
    ELSIF TG_OP = 'DELETE' THEN
        v_old_values := to_jsonb(OLD);
        BEGIN v_record_id := (v_old_values->>(LOWER(TG_TABLE_NAME)||'_id'))::INT; EXCEPTION WHEN OTHERS THEN NULL; END;
    END IF;

    INSERT INTO AuditLogs (
        user_id, role_id, action, table_name,
        record_id, old_values, new_values, ip_address, performed_at
    )
    VALUES (
        NULLIF(current_setting('app.current_user_id', TRUE), '')::INT,
        NULLIF(current_setting('app.current_role_id', TRUE), '')::INT,
        v_action,
        TG_TABLE_NAME,
        v_record_id,
        v_old_values,
        v_new_values,
        inet_client_addr(),
        NOW()
    );

    RETURN COALESCE(NEW, OLD);
END;
$$;


-- ─────────────────────────────────────────────
-- T1: Trigger on UserRole — log every role assignment / revocation
-- ─────────────────────────────────────────────
CREATE OR REPLACE TRIGGER trg_userrole_audit
AFTER INSERT OR UPDATE OR DELETE ON UserRole
FOR EACH ROW
EXECUTE FUNCTION fn_audit_log();


-- ─────────────────────────────────────────────
-- T2: Trigger on RolePermission — log permission grants / revocations
-- ─────────────────────────────────────────────
CREATE OR REPLACE TRIGGER trg_rolepermission_audit
AFTER INSERT OR UPDATE OR DELETE ON RolePermission
FOR EACH ROW
EXECUTE FUNCTION fn_audit_log();


-- ─────────────────────────────────────────────
-- T3: Trigger on Users — log account creation, lock events, updates
-- ─────────────────────────────────────────────
CREATE OR REPLACE TRIGGER trg_users_audit
AFTER INSERT OR UPDATE OR DELETE ON Users
FOR EACH ROW
EXECUTE FUNCTION fn_audit_log();


-- ─────────────────────────────────────────────
-- T4: Trigger on PrivilegeRequests — log all escalation request changes
-- ─────────────────────────────────────────────
CREATE OR REPLACE TRIGGER trg_privreq_audit
AFTER INSERT OR UPDATE OR DELETE ON PrivilegeRequests
FOR EACH ROW
EXECUTE FUNCTION fn_audit_log();


-- ─────────────────────────────────────────────
-- T5: Account lockout trigger
-- Automatically lock the account after 5 failed login attempts
-- (Simulate: UPDATE Users SET failed_login_count = failed_login_count + 1)
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION fn_auto_lockout()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.account_locked := TRUE;
    RAISE NOTICE 'Account % automatically locked after % failed attempts',
                 NEW.username, NEW.failed_login_count;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_account_lockout
BEFORE UPDATE OF failed_login_count ON Users
FOR EACH ROW
WHEN (NEW.failed_login_count >= 5 AND OLD.account_locked = FALSE)
EXECUTE FUNCTION fn_auto_lockout();


-- ─────────────────────────────────────────────
-- T6: Prevent privilege escalation without approval
-- Blocks INSERT into UserRole for privileged roles unless an APPROVED
-- PrivilegeRequest exists for that user/role combination
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION fn_check_escalation_approval()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_is_privileged BOOLEAN;
    v_existing_roles INT;
BEGIN
    -- Allow bypass for seeding scripts
    IF current_setting('app.is_seeding', TRUE) = 'true' THEN
        RETURN NEW;
    END IF;

    -- Only check for privileged roles
    SELECT is_privileged INTO v_is_privileged
    FROM   Roles WHERE role_id = NEW.role_id;

    IF v_is_privileged THEN
        -- Check if an approved request exists
        IF NOT EXISTS (
            SELECT 1 FROM PrivilegeRequests
            WHERE  requestor_id   = NEW.user_id
              AND  target_role_id = NEW.role_id
              AND  status         = 'APPROVED'
        )
        AND NOT EXISTS (
            -- Allow if assigning user is a SuperAdmin
            SELECT 1 FROM UserRole ur
            JOIN   Roles r ON r.role_id = ur.role_id
            WHERE  ur.user_id = NULLIF(current_setting('app.current_user_id', TRUE), '')::INT
              AND  r.role_name = 'SuperAdmin'
              AND  ur.is_active = TRUE
        ) THEN
            RAISE EXCEPTION
                'Privilege escalation blocked: no APPROVED request for user_id=% role_id=%',
                NEW.user_id, NEW.role_id;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_escalation_guard
BEFORE INSERT ON UserRole
FOR EACH ROW
EXECUTE FUNCTION fn_check_escalation_approval();


-- ─────────────────────────────────────────────
-- T7: Session expiry cleanup trigger
-- When a session is marked expired, set is_active = FALSE automatically
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION fn_expire_session()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.expires_at <= NOW() AND NEW.is_active = TRUE THEN
        NEW.is_active := FALSE;
        NEW.ended_at  := NEW.expires_at;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_session_expiry
BEFORE UPDATE ON Sessions
FOR EACH ROW
WHEN (NEW.expires_at <= NOW() AND NEW.is_active = TRUE)
EXECUTE FUNCTION fn_expire_session();


-- ─────────────────────────────────────────────
-- T8: updated_at auto-maintenance on Users
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION fn_update_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_users_updated_at
BEFORE UPDATE ON Users
FOR EACH ROW
EXECUTE FUNCTION fn_update_timestamp();
