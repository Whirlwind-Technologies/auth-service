package com.nnipa.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * User credentials for local authentication.
 * Stores password hashes and password history.
 */
@Entity
@Table(name = "user_credentials")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserCredential extends BaseEntity {

    @OneToOne
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "salt")
    private String salt; // Optional, BCrypt includes salt in hash

    @Column(name = "password_expires_at")
    private LocalDateTime passwordExpiresAt;

    @Column(name = "must_change_password")
    private Boolean mustChangePassword = false;

    @Column(name = "failed_attempts")
    private Integer failedAttempts = 0;

    @Column(name = "last_failed_attempt")
    private LocalDateTime lastFailedAttempt;

    @OneToMany(mappedBy = "credential", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @OrderBy("createdAt DESC")
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

    public boolean isPasswordExpired() {
        return passwordExpiresAt != null && passwordExpiresAt.isBefore(LocalDateTime.now());
    }
}