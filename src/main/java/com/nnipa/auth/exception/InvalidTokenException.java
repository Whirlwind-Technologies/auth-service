package com.nnipa.auth.exception;

/**
 * Exception thrown for invalid or expired tokens.
 */
public class InvalidTokenException extends RuntimeException {

    private String errorCode;

    public InvalidTokenException(String message) {
        super(message);
        this.errorCode = "INVALID_TOKEN";
    }

    public InvalidTokenException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = "INVALID_TOKEN";
    }

    public String getErrorCode() {
        return errorCode;
    }
}