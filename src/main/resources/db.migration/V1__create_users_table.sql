-- V1__create_users_table.sql
-- Create users table for authentication service

CREATE TABLE IF NOT EXISTS users (
                                     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    external_user_id UUID,
    username VARCHAR(100) UNIQUE,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    email VARCHAR(255) NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    phone_number VARCHAR(20),
    phone_verified BOOLEAN DEFAULT FALSE,
    status VARCHAR(30) NOT NULL DEFAULT 'PENDING_ACTIVATION',
    primary_auth_provider VARCHAR(30) NOT NULL DEFAULT 'LOCAL',
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    last_login_at TIMESTAMP,
    last_login_ip VARCHAR(45),
    password_changed_at TIMESTAMP,
    locked_until TIMESTAMP,
    lock_reason VARCHAR(500),
    activation_token VARCHAR(500),
    activation_token_expires_at TIMESTAMP,
    deleted_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    version BIGINT DEFAULT 0,

    CONSTRAINT chk_user_status CHECK (status IN (
                                      'PENDING_ACTIVATION', 'ACTIVE', 'INACTIVE',
                                      'SUSPENDED', 'LOCKED', 'EXPIRED', 'DELETED'
                                                )),

    CONSTRAINT chk_auth_provider CHECK (primary_auth_provider IN (
                                        'LOCAL', 'GOOGLE', 'GITHUB', 'MICROSOFT',
                                        'SAML', 'LDAP', 'OPENID'
                                                                 ))
    );

-- Create indexes for users table
CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_user_username ON users(username) WHERE username IS NOT NULL;
CREATE INDEX idx_user_tenant ON users(tenant_id);
CREATE INDEX idx_user_status ON users(status);
CREATE INDEX idx_user_provider ON users(primary_auth_provider);
CREATE INDEX idx_user_external_id ON users(external_user_id) WHERE external_user_id IS NOT NULL;

-- Create user_credentials table
CREATE TABLE IF NOT EXISTS user_credentials (
                                                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255),
    password_expires_at TIMESTAMP,
    must_change_password BOOLEAN DEFAULT FALSE,
    failed_attempts INTEGER DEFAULT 0,
    last_failed_attempt TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    version BIGINT DEFAULT 0
    );

CREATE INDEX idx_credential_user ON user_credentials(user_id);

-- Create password_history table
CREATE TABLE IF NOT EXISTS password_history (
                                                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id UUID NOT NULL REFERENCES user_credentials(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    version BIGINT DEFAULT 0
    );

CREATE INDEX idx_password_history_credential ON password_history(credential_id);

-- Create login_attempts table
CREATE TABLE IF NOT EXISTS login_attempts (
                                              id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(255),
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    attempt_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(500),
    auth_provider VARCHAR(30)
    );

CREATE INDEX idx_login_attempt_user ON login_attempts(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_login_attempt_ip ON login_attempts(ip_address);
CREATE INDEX idx_login_attempt_time ON login_attempts(attempt_time);
CREATE INDEX idx_login_attempt_username ON login_attempts(username) WHERE username IS NOT NULL;

-- Add comments
COMMENT ON TABLE users IS 'Core user table for authentication - profiles managed by user-management-service';
COMMENT ON COLUMN users.tenant_id IS 'Reference to tenant in tenant-management-service';
COMMENT ON COLUMN users.external_user_id IS 'Reference to user profile in user-management-service';
COMMENT ON COLUMN users.mfa_secret IS 'Encrypted TOTP secret for MFA';
COMMENT ON TABLE user_credentials IS 'Local authentication credentials';
COMMENT ON TABLE password_history IS 'Password history to prevent reuse';
COMMENT ON TABLE login_attempts IS 'Login attempt tracking for security and rate limiting';