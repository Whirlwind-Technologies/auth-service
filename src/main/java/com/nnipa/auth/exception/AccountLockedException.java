package com.nnipa.auth.exception;

import java.time.LocalDateTime;

/**
 * Exception thrown when account is locked.
 */
public class AccountLockedException extends AuthenticationException {

    private LocalDateTime lockedUntil;

    public AccountLockedException(String message) {
        super(message, "ACCOUNT_LOCKED");
    }

    public AccountLockedException(String message, LocalDateTime lockedUntil) {
        super(message, "ACCOUNT_LOCKED");
        this.lockedUntil = lockedUntil;
    }

    public LocalDateTime getLockedUntil() {
        return lockedUntil;
    }
}