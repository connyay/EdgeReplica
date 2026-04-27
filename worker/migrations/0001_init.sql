-- ============================================================================
-- Users + identities
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower
    ON users (LOWER(email));

CREATE TABLE IF NOT EXISTS identities (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    secret TEXT,
    created_at_ms INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS identities_provider_subject
    ON identities (provider, provider_user_id);

CREATE INDEX IF NOT EXISTS identities_by_user
    ON identities (user_id);

-- ============================================================================
-- Organizations + memberships
-- ============================================================================

CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    -- Personal orgs are auto-created at signup and tied to user lifecycle.
    personal INTEGER NOT NULL DEFAULT 0,
    owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS organizations_personal_owner
    ON organizations (owner_user_id) WHERE personal = 1;

CREATE TABLE IF NOT EXISTS org_memberships (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (user_id, org_id)
);

CREATE INDEX IF NOT EXISTS org_memberships_by_user
    ON org_memberships (user_id);
CREATE INDEX IF NOT EXISTS org_memberships_by_org
    ON org_memberships (org_id);

-- ============================================================================
-- Databases
-- ============================================================================

CREATE TABLE IF NOT EXISTS databases (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at_ms INTEGER NOT NULL,
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS databases_by_org
    ON databases (org_id);

-- ============================================================================
-- OAuth state (CSRF token for the redirect round trip)
-- ============================================================================

CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL
);
