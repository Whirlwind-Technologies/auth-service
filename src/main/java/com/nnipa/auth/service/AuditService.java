package com.nnipa.auth.service;

import com.nnipa.auth.entity.AuditLog;
import com.nnipa.auth.entity.SecurityEvent;
import com.nnipa.auth.enums.AuditEventType;
import com.nnipa.auth.enums.SecurityEventType;
import com.nnipa.auth.repository.AuditLogRepository;
import com.nnipa.auth.repository.SecurityEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Service for audit logging and security event tracking.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;
    private final SecurityEventRepository securityEventRepository;

    /**
     * Log authentication event.
     */
    @Async
    @Transactional
    public void logAuthenticationEvent(UUID userId, UUID tenantId, AuditEventType eventType,
                                       boolean success, String ipAddress, String userAgent,
                                       Map<String, Object> metadata) {
        log.debug("Logging authentication event: {} for user: {}", eventType, userId);

        AuditLog auditLog = AuditLog.builder()
                .userId(userId)
                .tenantId(tenantId)
                .eventType(eventType)
                .eventTime(LocalDateTime.now())
                .success(success)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .metadata(convertMetadataToJson(metadata))
                .build();

        auditLogRepository.save(auditLog);
    }

    /**
     * Log security event.
     */
    @Async
    @Transactional
    public void logSecurityEvent(UUID userId, SecurityEventType eventType, String description,
                                 String ipAddress, Map<String, Object> details) {
        log.info("Security event: {} for user: {} - {}", eventType, userId, description);

        SecurityEvent event = SecurityEvent.builder()
                .userId(userId)
                .eventType(eventType)
                .description(description)
                .ipAddress(ipAddress)
                .eventTime(LocalDateTime.now())
                .details(convertMetadataToJson(details))
                .resolved(false)
                .build();

        securityEventRepository.save(event);

        // Alert if critical security event
        if (isCriticalEvent(eventType)) {
            alertSecurityTeam(event);
        }
    }

    /**
     * Log password change.
     */
    public void logPasswordChange(UUID userId, UUID tenantId, String ipAddress, boolean forced) {
        Map<String, Object> metadata = Map.of(
                "forced", forced,
                "timestamp", LocalDateTime.now()
        );

        logAuthenticationEvent(userId, tenantId, AuditEventType.PASSWORD_CHANGE,
                true, ipAddress, null, metadata);
    }

    /**
     * Log MFA change.
     */
    public void logMfaChange(UUID userId, UUID tenantId, String action, String mfaType) {
        Map<String, Object> metadata = Map.of(
                "action", action,
                "mfaType", mfaType,
                "timestamp", LocalDateTime.now()
        );

        logAuthenticationEvent(userId, tenantId, AuditEventType.MFA_CHANGE,
                true, null, null, metadata);
    }

    /**
     * Log suspicious activity.
     */
    public void logSuspiciousActivity(UUID userId, String activity, String ipAddress,
                                      Map<String, Object> details) {
        logSecurityEvent(userId, SecurityEventType.SUSPICIOUS_ACTIVITY, activity,
                ipAddress, details);
    }

    /**
     * Get user's recent audit logs.
     */
    public List<AuditLog> getUserAuditLogs(UUID userId, int limit) {
        return auditLogRepository.findRecentByUserId(userId, limit);
    }

    /**
     * Get security events for user.
     */
    public List<SecurityEvent> getUserSecurityEvents(UUID userId, boolean includeResolved) {
        if (includeResolved) {
            return securityEventRepository.findByUserId(userId);
        }
        return securityEventRepository.findByUserIdAndResolved(userId, false);
    }

    /**
     * Mark security event as resolved.
     */
    @Transactional
    public void resolveSecurityEvent(UUID eventId, String resolution) {
        securityEventRepository.findById(eventId).ifPresent(event -> {
            event.setResolved(true);
            event.setResolvedAt(LocalDateTime.now());
            event.setResolution(resolution);
            securityEventRepository.save(event);
        });
    }

    /**
     * Clean up old audit logs.
     */
    @Transactional
    public void cleanupOldLogs(int daysToKeep) {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(daysToKeep);
        int deleted = auditLogRepository.deleteOldLogs(cutoff);
        log.info("Deleted {} audit logs older than {} days", deleted, daysToKeep);
    }

    // Private helper methods

    private String convertMetadataToJson(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }
        // Convert to JSON string (using Jackson or similar)
        return metadata.toString(); // Placeholder - use proper JSON serialization
    }

    private boolean isCriticalEvent(SecurityEventType eventType) {
        return eventType == SecurityEventType.BRUTE_FORCE_ATTACK ||
                eventType == SecurityEventType.ACCOUNT_TAKEOVER_ATTEMPT ||
                eventType == SecurityEventType.DATA_BREACH_ATTEMPT;
    }

    private void alertSecurityTeam(SecurityEvent event) {
        // Send alert to security team via notification service
        log.error("SECURITY ALERT: {} - User: {} - {}",
                event.getEventType(), event.getUserId(), event.getDescription());
    }
}