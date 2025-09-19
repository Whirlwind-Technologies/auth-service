package com.nnipa.auth.entity;

import com.nnipa.auth.enums.AuthProvider;
import com.nnipa.auth.enums.MfaType;
import com.nnipa.auth.enums.UserStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.Where;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * User entity - fixed version with MFA type support and metadata
 */
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email", unique = true),
        @Index(name = "idx_user_username", columnList = "username", unique = true),
        @Index(name = "idx_user_tenant", columnList = "tenant_id"),
        @Index(name = "idx_user_status", columnList = "status"),
        @Index(name = "idx_user_provider", columnList = "primary_auth_provider")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@SQLDelete(sql = "UPDATE users SET status = 'DELETED', deleted_at = CURRENT_TIMESTAMP WHERE id = ?")
@Where(clause = "status != 'DELETED'")
public class User extends BaseEntity {

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "external_user_id")
    private UUID externalUserId;

    @Column(name = "username", unique = true, length = 100)
    private String username;

    @Column(name = "first_name", length = 100)
    private String firstName;

    @Column(name = "last_name", length = 100)
    private String lastName;

    @Column(name = "email", nullable = false, unique = true, length = 255)
    private String email;

    @Column(name = "email_verified", nullable = false)
    private Boolean emailVerified = false;

    @Column(name = "phone_number", length = 20)
    private String phoneNumber;

    @Column(name = "phone_verified")
    private Boolean phoneVerified = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    private UserStatus status = UserStatus.PENDING_ACTIVATION;

    @Enumerated(EnumType.STRING)
    @Column(name = "primary_auth_provider", nullable = false, length = 30)
    private AuthProvider primaryAuthProvider = AuthProvider.LOCAL;

    @Column(name = "mfa_enabled")
    private Boolean mfaEnabled = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "mfa_type", length = 30)
    private MfaType mfaType;

    @Column(name = "mfa_secret")
    private String mfaSecret;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Column(name = "last_login_ip", length = 45)
    private String lastLoginIp;

    @Column(name = "password_changed_at")
    private LocalDateTime passwordChangedAt;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "lock_reason", length = 500)
    private String lockReason;

    @Column(name = "activation_token")
    private String activationToken;

    @Column(name = "activation_token_expires_at")
    private LocalDateTime activationTokenExpiresAt;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(
            name = "user_metadata",
            joinColumns = @JoinColumn(name = "user_id")
    )
    @MapKeyColumn(name = "metadata_key")
    @Column(name = "metadata_value")
    @Builder.Default
    private Map<String, String> metadata = new HashMap<>();

    // Relationships
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @Builder.Default
    private Set<UserCredential> credentials = new HashSet<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @Builder.Default
    private Set<OAuth2Account> oauth2Accounts = new HashSet<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @Builder.Default
    private Set<RefreshToken> refreshTokens = new HashSet<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @Builder.Default
    private Set<LoginAttempt> loginAttempts = new HashSet<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @Builder.Default
    private Set<MfaDevice> mfaDevices = new HashSet<>();

    // Helper methods
    public boolean isAccountLocked() {
        return lockedUntil != null && lockedUntil.isAfter(LocalDateTime.now());
    }

    public boolean isActive() {
        return status == UserStatus.ACTIVE && !isAccountLocked();
    }

    public boolean requiresPasswordChange() {
        if (passwordChangedAt == null) return true;
        return passwordChangedAt.plusDays(90).isBefore(LocalDateTime.now());
    }

    // Fixed method to get MFA type from primary enabled device
    public MfaType getMfaType() {
        if (this.mfaType != null) {
            return this.mfaType;
        }

        // Fallback: get from enabled MFA devices
        return mfaDevices.stream()
                .filter(MfaDevice::getEnabled)
                .filter(device -> device.getIsPrimary() != null && device.getIsPrimary())
                .map(MfaDevice::getType)
                .findFirst()
                .orElse(MfaType.TOTP); // Default fallback
    }

    // ADDED: Metadata convenience methods
    public void putMetadata(String key, String value) {
        if (this.metadata == null) {
            this.metadata = new HashMap<>();
        }
        this.metadata.put(key, value);
    }

    public String getMetadata(String key) {
        return this.metadata != null ? this.metadata.get(key) : null;
    }

    public void removeMetadata(String key) {
        if (this.metadata != null) {
            this.metadata.remove(key);
        }
    }
}