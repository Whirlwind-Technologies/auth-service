package com.nnipa.auth.enums;

/**
 * Multi-factor authentication types.
 */
public enum MfaType {
    TOTP("Time-based One-Time Password"),
    SMS("SMS Code"),
    EMAIL("Email Code"),
    BACKUP_CODES("Backup Codes"),
    HARDWARE_TOKEN("Hardware Token");

    private final String description;

    MfaType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}