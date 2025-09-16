package com.nnipa.auth.enums;

/**
 * Types of user credentials
 */
public enum CredentialType {
    PASSWORD,
    PIN,
    BIOMETRIC_FINGERPRINT,
    BIOMETRIC_FACE,
    HARDWARE_TOKEN,
    SOFTWARE_TOKEN,
    RECOVERY_CODE
}