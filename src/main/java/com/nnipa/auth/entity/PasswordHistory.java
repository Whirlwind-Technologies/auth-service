package com.nnipa.auth.entity;

import jakarta.persistence.*;
import lombok.*;

/**
 * Password history to prevent password reuse.
 */
@Entity
@Table(name = "password_history", indexes = {
        @Index(name = "idx_password_history_credential", columnList = "credential_id")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordHistory extends BaseEntity {

    @ManyToOne
    @JoinColumn(name = "credential_id", nullable = false)
    private UserCredential credential;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "salt")
    private String salt;
}