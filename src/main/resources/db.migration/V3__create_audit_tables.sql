-- V3__create_audit_tables.sql
-- Audit and security event tables for authentication service

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
                                          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID,
    tenant_id UUID,
    event_type VARCHAR(50) NOT NULL,
    event_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN,
    ip_address VARCHAR(45),
    user_agent TEXT,
    metadata TEXT, -- JSON data
    error_message VARCHAR(500),

    CONSTRAINT chk_audit_event_type CHECK (event_type IN (
                                           'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'LOGOUT',
                                           'PASSWORD_CHANGE', 'PASSWORD_RESET',
                                           'MFA_ENABLED', 'MFA_DISABLED', 'MFA_CHANGE',
                                           'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED',
                                           'TOKEN_REFRESH', 'SESSION_CREATED', 'SESSION_EXPIRED',
                                           'PERMISSION_DENIED', 'OAUTH_LOGIN', 'SAML_LOGIN',
                                           'ACCOUNT_ACTIVATED', 'ACCOUNT_DEACTIVATED'
                                                         ))
    );

-- Create indexes for audit_logs
CREATE INDEX idx_audit_user ON audit_logs(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX idx_audit_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_event_time ON audit_logs(event_time);
CREATE INDEX idx_audit_success ON audit_logs(success) WHERE success = FALSE;

-- Create security_events table
CREATE TABLE IF NOT EXISTS security_events (
                                               id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID,
    event_type VARCHAR(50) NOT NULL,
    description VARCHAR(500) NOT NULL,
    ip_address VARCHAR(45),
    event_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details TEXT, -- JSON data
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP,
    resolution VARCHAR(500),

    CONSTRAINT chk_security_event_type CHECK (event_type IN (
                                              'BRUTE_FORCE_ATTACK', 'SUSPICIOUS_ACTIVITY',
                                              'ACCOUNT_TAKEOVER_ATTEMPT', 'INVALID_TOKEN_USE',
                                              'CONCURRENT_SESSION_LIMIT', 'GEO_LOCATION_ANOMALY',
                                              'UNUSUAL_ACCESS_PATTERN', 'DATA_BREACH_ATTEMPT',
                                              'PRIVILEGE_ESCALATION_ATTEMPT', 'MFA_BYPASS_ATTEMPT'
                                                            ))
    );

-- Create indexes for security_events
CREATE INDEX idx_security_event_user ON security_events(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_security_event_type ON security_events(event_type);
CREATE INDEX idx_security_event_time ON security_events(event_time);
CREATE INDEX idx_security_event_resolved ON security_events(resolved);
CREATE INDEX idx_security_unresolved ON security_events(resolved, event_time) WHERE resolved = FALSE;

-- Create user_sessions table for session tracking
CREATE TABLE IF NOT EXISTS user_sessions (
                                             id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(500) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_info VARCHAR(500),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    terminated_at TIMESTAMP,
    termination_reason VARCHAR(255)
    );

CREATE INDEX idx_session_user ON user_sessions(user_id);
CREATE INDEX idx_session_token ON user_sessions(session_token);
CREATE INDEX idx_session_active ON user_sessions(is_active, expires_at) WHERE is_active = TRUE;
CREATE INDEX idx_session_expires ON user_sessions(expires_at);

-- Create trusted_devices table for device fingerprinting
CREATE TABLE IF NOT EXISTS trusted_devices (
                                               id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(500) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    browser VARCHAR(100),
    operating_system VARCHAR(100),
    ip_address VARCHAR(45),
    trusted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,

    CONSTRAINT uk_user_device UNIQUE (user_id, device_fingerprint)
    );

CREATE INDEX idx_trusted_device_user ON trusted_devices(user_id);
CREATE INDEX idx_trusted_device_active ON trusted_devices(is_active, expires_at) WHERE is_active = TRUE;

-- Add comments
COMMENT ON TABLE audit_logs IS 'Comprehensive audit trail for all authentication events';
COMMENT ON TABLE security_events IS 'Security events requiring investigation or action';
COMMENT ON TABLE user_sessions IS 'Active and historical user session tracking';
COMMENT ON TABLE trusted_devices IS 'Trusted device fingerprints for risk-based authentication';

-- Create function to auto-expire old sessions
CREATE OR REPLACE FUNCTION expire_old_sessions()
RETURNS void AS $$
BEGIN
UPDATE user_sessions
SET is_active = FALSE,
    terminated_at = CURRENT_TIMESTAMP,
    termination_reason = 'SESSION_EXPIRED'
WHERE is_active = TRUE
  AND expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Create function to detect concurrent sessions
CREATE OR REPLACE FUNCTION check_concurrent_sessions(p_user_id UUID, p_max_sessions INTEGER)
RETURNS INTEGER AS $$
DECLARE
active_count INTEGER;
BEGIN
SELECT COUNT(*) INTO active_count
FROM user_sessions
WHERE user_id = p_user_id
  AND is_active = TRUE
  AND expires_at > CURRENT_TIMESTAMP;

RETURN active_count;
END;
$$ LANGUAGE plpgsql;