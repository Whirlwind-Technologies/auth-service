package com.nnipa.auth.event;

import com.google.protobuf.Timestamp;
import com.nnipa.auth.entity.User;
import com.nnipa.auth.enums.SecurityEventType;
import com.nnipa.proto.auth.*;
import com.nnipa.proto.common.EventMetadata;
import com.nnipa.proto.common.Priority;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Service to publish authentication events to Kafka using Protobuf.
 * Events are consumed by notification-service and other downstream services.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthEventPublisher {

    private final KafkaTemplate<String, Object> kafkaTemplate;

    @Value("${spring.application.name:auth-service}")
    private String applicationName;

    @Value("${auth.kafka.topics.user-registered:nnipa.events.auth.user-registered}")
    private String userRegisteredTopic;

    @Value("${auth.kafka.topics.password-changed:nnipa.events.auth.password-changed}")
    private String passwordChangedTopic;

    @Value("${auth.kafka.topics.login-event:nnipa.events.auth.login}")
    private String loginEventTopic;

    @Value("${auth.kafka.topics.mfa-event:nnipa.events.auth.mfa}")
    private String mfaEventTopic;

    @Value("${auth.kafka.topics.security-alert:nnipa.events.auth.security-alert}")
    private String securityAlertTopic;

    @Value("${auth.kafka.topics.password-reset:nnipa.events.auth.password-reset}")
    private String passwordResetTopic;

    /**
     * Publish user registration event when a new user is created.
     * This event is consumed by notification-service to send activation email.
     */
    public void publishUserRegisteredEvent(User user, String activationToken) {
        try {
            log.info("Publishing UserRegisteredEvent for user: {}", user.getId());

            // Build the registration data nested message
            UserRegisteredEvent.RegistrationData registrationData = UserRegisteredEvent.RegistrationData.newBuilder()
                    .setUserId(user.getId().toString())
                    .setTenantId(user.getTenantId().toString())
                    .setEmail(user.getEmail())
                    .setUsername(user.getUsername() != null ? user.getUsername() : user.getEmail())
                    .setRegistrationMethod(user.getPrimaryAuthProvider().toString())
                    .setRegisteredAt(toTimestamp(user.getCreatedAt()))
                    .setEmailVerified(user.getEmailVerified())
                    .setRegistrationSource("web") // You may want to make this configurable
                    .setIpAddress("") // Add IP address parameter if available
                    .setUserAgent("") // Add user agent parameter if available
                    .putAdditionalInfo("phoneNumber", user.getPhoneNumber() != null ? user.getPhoneNumber() : "")
                    .putAdditionalInfo("status", user.getStatus().toString())
                    .putAdditionalInfo("mfaEnabled", String.valueOf(user.getMfaEnabled()))
                    .putAdditionalInfo("activationToken", activationToken)
                    .putAdditionalInfo("activationUrl", "https://app.nnipa.cloud/auth/activate?token=" + activationToken)
                    .build();

            // Build the main event message
            UserRegisteredEvent event = UserRegisteredEvent.newBuilder()
                    .setMetadata(createEventMetadata(
                            user.getTenantId().toString(),
                            user.getId().toString(),
                            Priority.PRIORITY_HIGH))
                    .setRegistration(registrationData)
                    .build();

            // Send to Kafka with user ID as the key for partitioning
            sendEvent(userRegisteredTopic, user.getId().toString(), event, "UserRegisteredEvent");

        } catch (Exception e) {
            log.error("Error publishing UserRegisteredEvent for user: {}", user.getId(), e);
            // Don't throw exception to avoid breaking the registration flow
        }
    }

    /**
     * Publish password changed event.
     * Consumed by notification-service to send confirmation email.
     */
    public void publishPasswordChangedEvent(User user, String ipAddress, boolean forced) {
        try {
            log.info("Publishing PasswordChangedEvent for user: {}", user.getId());

            PasswordChangedEvent event = PasswordChangedEvent.newBuilder()
                    .setMetadata(createEventMetadata(
                            user.getTenantId().toString(),
                            user.getId().toString(),
                            Priority.PRIORITY_MEDIUM))
                    .setUserId(user.getId().toString())
                    .setTenantId(user.getTenantId().toString())
                    .setChangedBy(user.getId().toString()) // User changed their own password
                    .setChangedAt(toTimestamp(LocalDateTime.now()))
                    .setForcedChange(forced)
                    .setChangeReason(forced ? "Admin forced change" : "User initiated change")
                    .build();

            sendEvent(passwordChangedTopic, user.getId().toString(), event, "PasswordChangedEvent");

        } catch (Exception e) {
            log.error("Error publishing PasswordChangedEvent for user: {}", user.getId(), e);
        }
    }

    /**
     * Publish login event for audit and analytics.
     */
    public void publishLoginEvent(User user, String ipAddress, String userAgent,
                                  boolean success, String failureReason) {
        try {
            log.debug("Publishing LoginEvent for user: {}", user.getId());

            if (success) {
                // Build login data for successful login
                UserLoginEvent.LoginData loginData = UserLoginEvent.LoginData.newBuilder()
                        .setUserId(user.getId().toString())
                        .setTenantId(user.getTenantId().toString())
                        .setEmail(user.getEmail())
                        .setUsername(user.getUsername() != null ? user.getUsername() : user.getEmail())
                        .setAuthenticationMethod(user.getPrimaryAuthProvider().toString())
                        .setIpAddress(ipAddress != null ? ipAddress : "")
                        .setUserAgent(userAgent != null ? userAgent : "")
                        .setSessionId(UUID.randomUUID().toString()) // Generate session ID
                        .setLoginTime(toTimestamp(LocalDateTime.now()))
                        .setMfaUsed(user.getMfaEnabled())
                        .setDeviceId("") // Add device ID if available
                        .build();

                UserLoginEvent event = UserLoginEvent.newBuilder()
                        .setMetadata(createEventMetadata(
                                user.getTenantId().toString(),
                                user.getId().toString(),
                                Priority.PRIORITY_LOW))
                        .setLogin(loginData)
                        .build();

                sendEvent(loginEventTopic, user.getId().toString(), event, "UserLoginEvent");
            } else {
                // Build failure data for failed login
                LoginFailedEvent.FailureData failureData = LoginFailedEvent.FailureData.newBuilder()
                        .setUsername(user.getUsername() != null ? user.getUsername() : user.getEmail())
                        .setTenantId(user.getTenantId().toString())
                        .setFailureReason(failureReason != null ? failureReason : "Unknown")
                        .setIpAddress(ipAddress != null ? ipAddress : "")
                        .setUserAgent(userAgent != null ? userAgent : "")
                        .setAttemptTime(toTimestamp(LocalDateTime.now()))
                        .setFailureCount(1) // You might want to track this separately
                        .setAccountLocked(false) // Determine based on your logic
                        .build();

                LoginFailedEvent event = LoginFailedEvent.newBuilder()
                        .setMetadata(createEventMetadata(
                                user.getTenantId().toString(),
                                user.getId().toString(),
                                Priority.PRIORITY_MEDIUM))
                        .setFailure(failureData)
                        .build();

                sendEvent(loginEventTopic, user.getId().toString(), event, "LoginFailedEvent");
            }

        } catch (Exception e) {
            log.error("Error publishing LoginEvent for user: {}", user.getId(), e);
        }
    }

    /**
     * Publish MFA enabled event.
     */
    public void publishMfaEnabledEvent(User user, String mfaType, String deviceName) {
        try {
            log.info("Publishing MfaEnabledEvent for user: {} - type: {}", user.getId(), mfaType);

            MFAEnabledEvent event = MFAEnabledEvent.newBuilder()
                    .setMetadata(createEventMetadata(
                            user.getTenantId().toString(),
                            user.getId().toString(),
                            Priority.PRIORITY_MEDIUM))
                    .setUserId(user.getId().toString())
                    .setTenantId(user.getTenantId().toString())
                    .setMfaType(mfaType)
                    .setEnabledAt(toTimestamp(LocalDateTime.now()))
                    .setDeviceName(deviceName != null ? deviceName : "")
                    .build();

            sendEvent(mfaEventTopic, user.getId().toString(), event, "MFAEnabledEvent");

        } catch (Exception e) {
            log.error("Error publishing MfaEnabledEvent for user: {}", user.getId(), e);
        }
    }

    /**
     * Publish MFA disabled event.
     */
    public void publishMfaDisabledEvent(User user, String mfaType, String disabledBy, String reason) {
        try {
            log.info("Publishing MfaDisabledEvent for user: {} - type: {}", user.getId(), mfaType);

            MFADisabledEvent event = MFADisabledEvent.newBuilder()
                    .setMetadata(createEventMetadata(
                            user.getTenantId().toString(),
                            user.getId().toString(),
                            Priority.PRIORITY_MEDIUM))
                    .setUserId(user.getId().toString())
                    .setTenantId(user.getTenantId().toString())
                    .setMfaType(mfaType)
                    .setDisabledAt(toTimestamp(LocalDateTime.now()))
                    .setDisabledBy(disabledBy)
                    .setReason(reason != null ? reason : "")
                    .build();

            sendEvent(mfaEventTopic, user.getId().toString(), event, "MFADisabledEvent");

        } catch (Exception e) {
            log.error("Error publishing MfaDisabledEvent for user: {}", user.getId(), e);
        }
    }

    /**
     * Publish account locked event.
     */
    public void publishAccountLockedEvent(User user, String lockReason, int failedAttempts, LocalDateTime unlockAt) {
        try {
            log.warn("Publishing AccountLockedEvent for user: {} - reason: {}", user.getId(), lockReason);

            AccountLockedEvent event = AccountLockedEvent.newBuilder()
                    .setMetadata(createEventMetadata(
                            user.getTenantId().toString(),
                            user.getId().toString(),
                            Priority.PRIORITY_CRITICAL))
                    .setUserId(user.getId().toString())
                    .setTenantId(user.getTenantId().toString())
                    .setLockReason(lockReason)
                    .setLockedAt(toTimestamp(LocalDateTime.now()))
                    .setUnlockAt(unlockAt != null ? toTimestamp(unlockAt) : toTimestamp(LocalDateTime.now().plusHours(24)))
                    .setFailedAttempts(failedAttempts)
                    .build();

            sendEvent(securityAlertTopic, user.getId().toString(), event, "AccountLockedEvent");

        } catch (Exception e) {
            log.error("Error publishing AccountLockedEvent for user: {}", user.getId(), e);
        }
    }

    /**
     * Publish password reset requested event.
     * Consumed by notification-service to send reset email.
     */
    public void publishPasswordResetRequestedEvent(User user, String resetToken, String ipAddress) {
        try {
            log.info("Publishing PasswordResetRequestedEvent for user: {}", user.getId());

            PasswordResetRequestedEvent event = PasswordResetRequestedEvent.newBuilder()
                    .setMetadata(createEventMetadata(
                            user.getTenantId().toString(),
                            user.getId().toString(),
                            Priority.PRIORITY_HIGH))
                    .setUserId(user.getId().toString())
                    .setEmail(user.getEmail())
                    .setTenantId(user.getTenantId().toString())
                    .setResetToken(resetToken)
                    .setRequestedAt(toTimestamp(LocalDateTime.now()))
                    .setExpiresAt(toTimestamp(LocalDateTime.now().plusHours(1)))
                    .setIpAddress(ipAddress != null ? ipAddress : "")
                    .build();

            sendEvent(passwordResetTopic, user.getId().toString(), event, "PasswordResetRequestedEvent");

        } catch (Exception e) {
            log.error("Error publishing PasswordResetRequestedEvent for user: {}", user.getId(), e);
        }
    }

    /**
     * Publish password reset completed event.
     */
    public void publishPasswordResetCompletedEvent(User user, String ipAddress) {
        try {
            log.info("Publishing PasswordResetCompletedEvent for user: {}", user.getId());

            PasswordResetCompletedEvent event = PasswordResetCompletedEvent.newBuilder()
                    .setMetadata(createEventMetadata(
                            user.getTenantId().toString(),
                            user.getId().toString(),
                            Priority.PRIORITY_HIGH))
                    .setUserId(user.getId().toString())
                    .setTenantId(user.getTenantId().toString())
                    .setResetAt(toTimestamp(LocalDateTime.now()))
                    .setIpAddress(ipAddress != null ? ipAddress : "")
                    .build();

            sendEvent(passwordResetTopic, user.getId().toString(), event, "PasswordResetCompletedEvent");

        } catch (Exception e) {
            log.error("Error publishing PasswordResetCompletedEvent for user: {}", user.getId(), e);
        }
    }

    // Private helper methods

    /**
     * Send event to Kafka with error handling and logging.
     */
    private void sendEvent(String topic, String key, Object event, String eventType) {
        CompletableFuture<SendResult<String, Object>> future =
                kafkaTemplate.send(topic, key, event);

        future.whenComplete((result, ex) -> {
            if (ex == null) {
                log.info("{} sent successfully to topic: {} with key: {} at offset: {}",
                        eventType, topic, key, result.getRecordMetadata().offset());
            } else {
                log.error("Failed to send {} to topic: {} with key: {}",
                        eventType, topic, key, ex);
                // Could implement retry logic or dead letter queue here
            }
        });
    }

    /**
     * Create event metadata with standard fields.
     */
    private EventMetadata createEventMetadata(String tenantId, String userId, Priority priority) {
        return EventMetadata.newBuilder()
                .setEventId(UUID.randomUUID().toString())
                .setCorrelationId(UUID.randomUUID().toString())
                .setSourceService(applicationName)
                .setTimestamp(toTimestamp(LocalDateTime.now()))
                .setVersion(1)
                .setTenantId(tenantId)
                .setUserId(userId)
                .setPriority(priority)
                .setRetryCount(0)
                .putHeaders("content-type", "application/x-protobuf")
                .putHeaders("schema-version", "1.0")
                .build();
    }

    /**
     * Convert LocalDateTime to Protobuf Timestamp.
     */
    private Timestamp toTimestamp(LocalDateTime dateTime) {
        if (dateTime == null) {
            dateTime = LocalDateTime.now();
        }
        Instant instant = dateTime.toInstant(ZoneOffset.UTC);
        return Timestamp.newBuilder()
                .setSeconds(instant.getEpochSecond())
                .setNanos(instant.getNano())
                .build();
    }

    /**
     * Map security event type to severity level.
     */
    private String mapSeverity(SecurityEventType eventType) {
        return switch (eventType) {
            case BRUTE_FORCE_ATTACK, ACCOUNT_TAKEOVER_ATTEMPT, DATA_BREACH_ATTEMPT -> "CRITICAL";
            case PRIVILEGE_ESCALATION_ATTEMPT, MFA_BYPASS_ATTEMPT -> "HIGH";
            case SUSPICIOUS_ACTIVITY, INVALID_TOKEN_USE -> "MEDIUM";
            default -> "LOW";
        };
    }
}