package com.nnipa.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Login attempt tracking for security and audit purposes.
 */
@Entity
@Table(name = "login_attempts", indexes = {
        @Index(name = "idx_login_attempt_user", columnList = "user_id"),
        @Index(name = "idx_login_attempt_ip", columnList = "ip_address"),
        @Index(name = "idx_login_attempt_time", columnList = "attempt_time")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private java.util.UUID id;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "username", length = 255)
    private String username;

    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    @Column(name = "attempt_time", nullable = false)
    private LocalDateTime attemptTime;

    @Column(name = "success", nullable = false)
    private Boolean success;

    @Column(name = "failure_reason", length = 500)
    private String failureReason;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_provider", length = 30)
    private com.nnipa.auth.enums.AuthProvider authProvider;

    @PrePersist
    protected void onCreate() {
        if (attemptTime == null) {
            attemptTime = LocalDateTime.now();
        }
    }
}