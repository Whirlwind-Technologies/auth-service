package com.nnipa.auth.exception;

/**
 * Exception thrown when MFA verification is required.
 */
public class MfaRequiredException extends AuthenticationException {

    private String mfaToken;

    public MfaRequiredException(String message) {
        super(message, "MFA_REQUIRED");
    }

    public MfaRequiredException(String message, String mfaToken) {
        super(message, "MFA_REQUIRED");
        this.mfaToken = mfaToken;
    }

    public String getMfaToken() {
        return mfaToken;
    }
}