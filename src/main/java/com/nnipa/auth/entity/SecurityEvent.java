package com.nnipa.auth.entity;

import com.nnipa.auth.enums.SecurityEventType;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "security_events", indexes = {
        @Index(name = "idx_security_event_user", columnList = "user_id"),
        @Index(name = "idx_security_event_type", columnList = "event_type"),
        @Index(name = "idx_security_event_time", columnList = "event_time"),
        @Index(name = "idx_security_event_resolved", columnList = "resolved")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id")
    private UUID userId;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false)
    private SecurityEventType eventType;

    @Column(name = "description", nullable = false)
    private String description;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "event_time", nullable = false)
    private LocalDateTime eventTime;

    @Column(name = "details", columnDefinition = "TEXT")
    private String details;

    @Column(name = "resolved")
    private Boolean resolved;

    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;

    @Column(name = "resolution")
    private String resolution;
}