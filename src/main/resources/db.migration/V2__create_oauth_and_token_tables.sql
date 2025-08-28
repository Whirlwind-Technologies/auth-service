-- V2__create_oauth_and_token_tables.sql
-- OAuth2 accounts and token management tables

-- Create oauth2_accounts table
CREATE TABLE IF NOT EXISTS oauth2_accounts (
                                               id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(30) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    provider_username VARCHAR(255),
    provider_email VARCHAR(255),
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMP,
    provider_data TEXT, -- JSON data from provider
    linked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    version BIGINT DEFAULT 0,

    CONSTRAINT uk_oauth2_provider_account UNIQUE (provider, provider_user_id),
    CONSTRAINT chk_oauth2_provider CHECK (provider IN (
                                          'GOOGLE', 'GITHUB', 'MICROSOFT', 'SAML', 'LDAP', 'OPENID'
                                                      ))
    );

CREATE INDEX idx_oauth2_user ON oauth2_accounts(user_id);
CREATE INDEX idx_oauth2_provider ON oauth2_accounts(provider);
CREATE INDEX idx_oauth2_provider_user ON oauth2_accounts(provider_user_id);

-- Create refresh_tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
                                              id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(500) NOT NULL UNIQUE,
    device_info VARCHAR(500),
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    revoked_reason VARCHAR(500),
    replaced_by_token VARCHAR(500),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    version BIGINT DEFAULT 0
    );

CREATE INDEX idx_refresh_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_token_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_token_expires ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_token_revoked ON refresh_tokens(revoked) WHERE revoked = FALSE;

-- Create mfa_devices table
CREATE TABLE IF NOT EXISTS mfa_devices (
                                           id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(30) NOT NULL,
    device_name VARCHAR(255),
    secret VARCHAR(500),
    phone_number VARCHAR(20),
    email VARCHAR(255),
    backup_codes TEXT, -- Encrypted JSON array
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMP,
    last_used_at TIMESTAMP,
    is_primary BOOLEAN DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    version BIGINT DEFAULT 0,

    CONSTRAINT chk_mfa_type CHECK (type IN (
                                   'TOTP', 'SMS', 'EMAIL', 'BACKUP_CODES', 'HARDWARE_TOKEN'
                                           ))
    );

CREATE INDEX idx_mfa_device_user ON mfa_devices(user_id);
CREATE INDEX idx_mfa_device_type ON mfa_devices(type);
CREATE INDEX idx_mfa_device_enabled ON mfa_devices(enabled) WHERE enabled = TRUE;

-- Create session blacklist table (for logout and token invalidation)
CREATE TABLE IF NOT EXISTS session_blacklist (
                                                 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_jti VARCHAR(255) NOT NULL UNIQUE, -- JWT ID
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    blacklisted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    reason VARCHAR(255)
    );

CREATE INDEX idx_blacklist_jti ON session_blacklist(token_jti);
CREATE INDEX idx_blacklist_expires ON session_blacklist(expires_at);
CREATE INDEX idx_blacklist_user ON session_blacklist(user_id) WHERE user_id IS NOT NULL;

-- Create password reset tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
                                                     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(500) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

CREATE INDEX idx_password_reset_token ON password_reset_tokens(token);
CREATE INDEX idx_password_reset_user ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_expires ON password_reset_tokens(expires_at);
CREATE INDEX idx_password_reset_unused ON password_reset_tokens(used) WHERE used = FALSE;

-- Add comments
COMMENT ON TABLE oauth2_accounts IS 'OAuth2 linked accounts for external authentication';
COMMENT ON TABLE refresh_tokens IS 'JWT refresh tokens for token renewal';
COMMENT ON TABLE mfa_devices IS 'Multi-factor authentication devices and methods';
COMMENT ON TABLE session_blacklist IS 'Blacklisted JWT tokens for logout functionality';
COMMENT ON TABLE password_reset_tokens IS 'Password reset tokens with expiration';