package com.nnipa.auth.entity;

import com.nnipa.auth.enums.AuthProvider;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * OAuth2 account linking for external authentication providers.
 */
@Entity
@Table(name = "oauth2_accounts",
        uniqueConstraints = @UniqueConstraint(columnNames = {"provider", "provider_user_id"}),
        indexes = {
                @Index(name = "idx_oauth2_user", columnList = "user_id"),
                @Index(name = "idx_oauth2_provider", columnList = "provider")
        })
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2Account extends BaseEntity {

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false, length = 30)
    private AuthProvider provider;

    @Column(name = "provider_user_id", nullable = false, length = 255)
    private String providerUserId;

    @Column(name = "provider_username", length = 255)
    private String providerUsername;

    @Column(name = "provider_email", length = 255)
    private String providerEmail;

    @Column(name = "access_token", columnDefinition = "TEXT")
    private String accessToken;

    @Column(name = "refresh_token", columnDefinition = "TEXT")
    private String refreshToken;

    @Column(name = "token_expires_at")
    private LocalDateTime tokenExpiresAt;

    @Column(name = "provider_data", columnDefinition = "TEXT")
    private String providerData; // JSON data from provider

    @Column(name = "linked_at", nullable = false)
    private LocalDateTime linkedAt;

    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    protected void onPrePersist() {
        if (linkedAt == null) {
            linkedAt = LocalDateTime.now();
        }
    }

    public boolean isTokenExpired() {
        return tokenExpiresAt != null && tokenExpiresAt.isBefore(LocalDateTime.now());
    }
}