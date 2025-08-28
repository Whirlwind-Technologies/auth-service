package com.nnipa.auth.exception;

/**
 * Exception thrown for authentication failures.
 */
public class AuthenticationException extends RuntimeException {

    private String errorCode;

    public AuthenticationException(String message) {
        super(message);
        this.errorCode = "AUTH_ERROR";
    }

    public AuthenticationException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = "AUTH_ERROR";
    }

    public String getErrorCode() {
        return errorCode;
    }
}