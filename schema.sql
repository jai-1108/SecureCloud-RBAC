-- ============================================================
-- RBAC System with Cloud Access Control Dataset Integration
-- schema.sql — Database Schema (PostgreSQL compatible)
-- ============================================================

-- ─────────────────────────────────────────────
-- ENUM TYPES
-- ─────────────────────────────────────────────
CREATE TYPE auth_mechanism   AS ENUM ('Password','MFA','SSO','Biometric');
CREATE TYPE auth_model       AS ENUM ('RBAC','ABAC','PBAC');
CREATE TYPE access_level     AS ENUM ('Read','Write','Modify','Admin');
CREATE TYPE data_sensitivity AS ENUM ('Public','Private','Confidential','Highly Confidential');
CREATE TYPE cloud_provider   AS ENUM ('AWS','Azure','GCP','IBM Cloud');
CREATE TYPE action_type      AS ENUM ('INSERT','UPDATE','DELETE');
CREATE TYPE compliance_type  AS ENUM ('GDPR','HIPAA','SOX','OAuth','NIST');

-- ─────────────────────────────────────────────
-- USERS
-- ─────────────────────────────────────────────
CREATE TABLE Users (
    user_id            SERIAL          PRIMARY KEY,
    username           VARCHAR(100)    NOT NULL UNIQUE,
    email              VARCHAR(200)    NOT NULL UNIQUE,
    full_name          VARCHAR(200)    NOT NULL,
    auth_mechanism     auth_mechanism  NOT NULL DEFAULT 'Password',
    identity_verified  BOOLEAN         NOT NULL DEFAULT FALSE,
    geolocation        VARCHAR(100),
    cloud_provider     cloud_provider,
    is_active          BOOLEAN         NOT NULL DEFAULT TRUE,
    account_locked     BOOLEAN         NOT NULL DEFAULT FALSE,
    failed_login_count INT             NOT NULL DEFAULT 0
                       CHECK (failed_login_count >= 0),
    created_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────
-- ROLES
-- ─────────────────────────────────────────────
CREATE TABLE Roles (
    role_id          SERIAL       PRIMARY KEY,
    role_name        VARCHAR(100) NOT NULL UNIQUE,
    description      TEXT,
    auth_model       auth_model   NOT NULL DEFAULT 'RBAC',
    is_privileged    BOOLEAN      NOT NULL DEFAULT FALSE,
    is_active        BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────
-- ROLE HIERARCHY  (parent inherits from child)
-- ─────────────────────────────────────────────
CREATE TABLE RoleHierarchy (
    hierarchy_id  SERIAL      PRIMARY KEY,
    parent_role   INT         NOT NULL REFERENCES Roles(role_id) ON DELETE CASCADE,
    child_role    INT         NOT NULL REFERENCES Roles(role_id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (parent_role, child_role),
    CHECK (parent_role <> child_role)
);

-- ─────────────────────────────────────────────
-- PERMISSIONS
-- ─────────────────────────────────────────────
CREATE TABLE Permissions (
    permission_id        SERIAL          PRIMARY KEY,
    permission_name      VARCHAR(150)    NOT NULL UNIQUE,
    resource             VARCHAR(200)    NOT NULL,
    access_level         access_level    NOT NULL,
    data_sensitivity     data_sensitivity NOT NULL DEFAULT 'Public',
    requires_mfa         BOOLEAN         NOT NULL DEFAULT FALSE,
    time_restricted      BOOLEAN         NOT NULL DEFAULT FALSE,
    geo_restricted       BOOLEAN         NOT NULL DEFAULT FALSE,
    api_permission       BOOLEAN         NOT NULL DEFAULT FALSE,
    compliance_tag       compliance_type,
    is_active            BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at           TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────
-- USER ↔ ROLE  (junction)
-- ─────────────────────────────────────────────
CREATE TABLE UserRole (
    user_role_id  SERIAL      PRIMARY KEY,
    user_id       INT         NOT NULL REFERENCES Users(user_id)  ON DELETE CASCADE,
    role_id       INT         NOT NULL REFERENCES Roles(role_id)  ON DELETE CASCADE,
    assigned_by   INT                  REFERENCES Users(user_id)  ON DELETE SET NULL,
    assigned_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ,
    is_active     BOOLEAN     NOT NULL DEFAULT TRUE,
    UNIQUE (user_id, role_id)
);

-- ─────────────────────────────────────────────
-- ROLE ↔ PERMISSION  (junction)
-- ─────────────────────────────────────────────
CREATE TABLE RolePermission (
    role_permission_id SERIAL      PRIMARY KEY,
    role_id            INT         NOT NULL REFERENCES Roles(role_id)       ON DELETE CASCADE,
    permission_id      INT         NOT NULL REFERENCES Permissions(permission_id) ON DELETE CASCADE,
    granted_by         INT                  REFERENCES Users(user_id)       ON DELETE SET NULL,
    granted_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active          BOOLEAN     NOT NULL DEFAULT TRUE,
    UNIQUE (role_id, permission_id)
);

-- ─────────────────────────────────────────────
-- SESSIONS
-- ─────────────────────────────────────────────
CREATE TABLE Sessions (
    session_id      SERIAL          PRIMARY KEY,
    user_id         INT             NOT NULL REFERENCES Users(user_id) ON DELETE CASCADE,
    session_token   VARCHAR(512)    NOT NULL UNIQUE,
    ip_address      INET,
    geolocation     VARCHAR(100),
    cloud_provider  cloud_provider,
    auth_mechanism  auth_mechanism  NOT NULL,
    started_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ     NOT NULL,
    ended_at        TIMESTAMPTZ,
    is_active       BOOLEAN         NOT NULL DEFAULT TRUE,
    CHECK (expires_at > started_at)
);

-- ─────────────────────────────────────────────
-- POLICIES  (fine-grained access rules)
-- ─────────────────────────────────────────────
CREATE TABLE Policies (
    policy_id         SERIAL         PRIMARY KEY,
    policy_name       VARCHAR(200)   NOT NULL UNIQUE,
    description       TEXT,
    auth_model        auth_model     NOT NULL DEFAULT 'RBAC',
    zero_trust        BOOLEAN        NOT NULL DEFAULT FALSE,
    least_privilege   BOOLEAN        NOT NULL DEFAULT TRUE,
    dlp_enabled       BOOLEAN        NOT NULL DEFAULT FALSE,
    mfa_required      BOOLEAN        NOT NULL DEFAULT FALSE,
    geo_restriction   VARCHAR(200),
    time_window_start TIME,
    time_window_end   TIME,
    compliance_tag    compliance_type,
    security_score    SMALLINT       CHECK (security_score BETWEEN 1 AND 5),
    is_active         BOOLEAN        NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────
-- POLICY ↔ ROLE  (many-to-many)
-- ─────────────────────────────────────────────
CREATE TABLE PolicyRole (
    policy_role_id SERIAL      PRIMARY KEY,
    policy_id      INT         NOT NULL REFERENCES Policies(policy_id)  ON DELETE CASCADE,
    role_id        INT         NOT NULL REFERENCES Roles(role_id)       ON DELETE CASCADE,
    UNIQUE (policy_id, role_id)
);

-- ─────────────────────────────────────────────
-- AUDIT LOGS
-- ─────────────────────────────────────────────
CREATE TABLE AuditLogs (
    audit_id      BIGSERIAL    PRIMARY KEY,
    user_id       INT                   REFERENCES Users(user_id)  ON DELETE SET NULL,
    role_id       INT                   REFERENCES Roles(role_id)  ON DELETE SET NULL,
    action        action_type  NOT NULL,
    table_name    VARCHAR(100) NOT NULL,
    record_id     INT,
    old_values    JSONB,
    new_values    JSONB,
    ip_address    INET,
    performed_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────
-- PRIVILEGE ESCALATION REQUESTS
-- ─────────────────────────────────────────────
CREATE TABLE PrivilegeRequests (
    request_id      SERIAL       PRIMARY KEY,
    requestor_id    INT          NOT NULL REFERENCES Users(user_id) ON DELETE CASCADE,
    target_role_id  INT          NOT NULL REFERENCES Roles(role_id) ON DELETE CASCADE,
    justification   TEXT         NOT NULL,
    status          VARCHAR(20)  NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING','APPROVED','DENIED','REVOKED')),
    reviewed_by     INT                   REFERENCES Users(user_id) ON DELETE SET NULL,
    requested_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    reviewed_at     TIMESTAMPTZ
);
