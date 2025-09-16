package com.nnipa.auth.entity;

import com.nnipa.auth.enums.CredentialType;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * User credentials entity - fixed version
 */
@Entity
@Table(name = "user_credentials", indexes = {
        @Index(name = "idx_credential_user_type", columnList = "user_id, type", unique = true)
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserCredential extends BaseEntity {

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false, length = 30)
    private CredentialType type;

    @Column(name = "credential_value", nullable = false)
    private String credentialValue; // This was missing - contains the actual password hash

    @Column(name = "salt")
    private String salt;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "must_change_password")
    private Boolean mustChangePassword = false;

    @Column(name = "failed_attempts")
    private Integer failedAttempts = 0;

    @Column(name = "last_failed_attempt")
    private LocalDateTime lastFailedAttempt;

    // Relationships
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", insertable = false, updatable = false)
    private User user;

    @OneToMany(mappedBy = "credential", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @OrderBy("createdAt DESC")
    @Builder.Default
    private Set<PasswordHistory> passwordHistory = new HashSet<>();

    // Helper methods
    public void incrementFailedAttempts() {
        this.failedAttempts = (this.failedAttempts == null ? 0 : this.failedAttempts) + 1;
        this.lastFailedAttempt = LocalDateTime.now();
    }

    public void resetFailedAttempts() {
        this.failedAttempts = 0;
        this.lastFailedAttempt = null;
    }

    public boolean isExpired() {
        return expiresAt != null && expiresAt.isBefore(LocalDateTime.now());
    }
}
