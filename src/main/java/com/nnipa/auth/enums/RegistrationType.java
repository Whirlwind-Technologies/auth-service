package com.nnipa.auth.enums;

/**
 * Registration type enumeration.
 */
public enum RegistrationType {
    SELF_SIGNUP,      // New user creating new tenant
    ADMIN_CREATED     // Admin creating user for existing tenant
}