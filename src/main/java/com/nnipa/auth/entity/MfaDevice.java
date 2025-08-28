package com.nnipa.auth.entity;

import com.nnipa.auth.enums.MfaType;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Multi-factor authentication devices/methods for users.
 */
@Entity
@Table(name = "mfa_devices", indexes = {
        @Index(name = "idx_mfa_device_user", columnList = "user_id")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MfaDevice extends BaseEntity {

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false, length = 30)
    private MfaType type;

    @Column(name = "device_name", length = 255)
    private String deviceName;

    @Column(name = "secret")
    private String secret;

    @Column(name = "phone_number", length = 20)
    private String phoneNumber;

    @Column(name = "email", length = 255)
    private String email;

    @Column(name = "backup_codes", columnDefinition = "TEXT")
    private String backupCodes; // JSON array of encrypted backup codes

    @Column(name = "verified", nullable = false)
    private Boolean verified = false;

    @Column(name = "verified_at")
    private LocalDateTime verifiedAt;

    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    @Column(name = "is_primary")
    private Boolean isPrimary = false;

    @Column(name = "enabled", nullable = false)
    private Boolean enabled = true;
}