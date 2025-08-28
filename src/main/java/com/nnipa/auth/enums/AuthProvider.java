package com.nnipa.auth.enums;

/**
 * Authentication provider types supported by the system.
 */
public enum AuthProvider {
    LOCAL("local"),
    GOOGLE("google"),
    GITHUB("github"),
    MICROSOFT("microsoft"),
    SAML("saml"),
    LDAP("ldap"),
    OPENID("openid");

    private final String provider;

    AuthProvider(String provider) {
        this.provider = provider;
    }

    public String getProvider() {
        return provider;
    }
}