package com.nnipa.auth.integration;

import com.nnipa.auth.entity.User;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * Client for integrating with Notification Service.
 * This is a placeholder implementation - actual implementation would depend on
 * the notification service API specification.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class NotificationServiceClient {

    private final RestTemplate restTemplate;

    @Value("${services.notification-service.url}")
    private String notificationServiceUrl;

    /**
     * Send password change notification.
     */
    @CircuitBreaker(name = "notification-service", fallbackMethod = "fallbackNotification")
    @Retry(name = "notification-service")
    public void sendPasswordChangeNotification(User user) {
        log.info("Sending password change notification for user: {}", user.getId());

        Map<String, Object> notification = new HashMap<>();
        notification.put("userId", user.getId());
        notification.put("email", user.getEmail());
        notification.put("type", "PASSWORD_CHANGE");
        notification.put("subject", "Password Changed");
        notification.put("template", "password-change");
        notification.put("data", Map.of(
                "username", user.getUsername() != null ? user.getUsername() : user.getEmail(),
                "changeTime", System.currentTimeMillis()
        ));

        sendNotification(notification);
    }

    /**
     * Send password reset email.
     */
    @CircuitBreaker(name = "notification-service", fallbackMethod = "fallbackNotification")
    @Retry(name = "notification-service")
    public void sendPasswordResetEmail(User user, String resetToken) {
        log.info("Sending password reset email to: {}", user.getEmail());

        String resetLink = "https://app.nnipa.cloud/auth/reset-password?token=" + resetToken;

        Map<String, Object> notification = new HashMap<>();
        notification.put("userId", user.getId());
        notification.put("email", user.getEmail());
        notification.put("type", "PASSWORD_RESET");
        notification.put("subject", "Reset Your Password");
        notification.put("template", "password-reset");
        notification.put("data", Map.of(
                "username", user.getUsername() != null ? user.getUsername() : user.getEmail(),
                "resetLink", resetLink,
                "expiresIn", "1 hour"
        ));

        sendNotification(notification);
    }

    /**
     * Send password reset confirmation.
     */
    @CircuitBreaker(name = "notification-service", fallbackMethod = "fallbackNotification")
    @Retry(name = "notification-service")
    public void sendPasswordResetConfirmation(User user) {
        log.info("Sending password reset confirmation to: {}", user.getEmail());

        Map<String, Object> notification = new HashMap<>();
        notification.put("userId", user.getId());
        notification.put("email", user.getEmail());
        notification.put("type", "PASSWORD_RESET_CONFIRMATION");
        notification.put("subject", "Password Reset Successful");
        notification.put("template", "password-reset-success");
        notification.put("data", Map.of(
                "username", user.getUsername() != null ? user.getUsername() : user.getEmail()
        ));

        sendNotification(notification);
    }

    /**
     * Send account activation email.
     */
    @CircuitBreaker(name = "notification-service", fallbackMethod = "fallbackNotification")
    @Retry(name = "notification-service")
    public void sendActivationEmail(User user, String activationToken) {
        log.info("Sending activation email to: {}", user.getEmail());

        String activationLink = "https://app.nnipa.cloud/auth/activate?token=" + activationToken;

        Map<String, Object> notification = new HashMap<>();
        notification.put("userId", user.getId());
        notification.put("email", user.getEmail());
        notification.put("type", "ACCOUNT_ACTIVATION");
        notification.put("subject", "Activate Your Account");
        notification.put("template", "account-activation");
        notification.put("data", Map.of(
                "username", user.getUsername() != null ? user.getUsername() : user.getEmail(),
                "activationLink", activationLink,
                "expiresIn", "7 days"
        ));

        sendNotification(notification);
    }

    /**
     * Send MFA enabled notification.
     */
    @CircuitBreaker(name = "notification-service", fallbackMethod = "fallbackNotification")
    @Retry(name = "notification-service")
    public void sendMfaEnabledNotification(User user, String mfaType) {
        log.info("Sending MFA enabled notification to: {}", user.getEmail());

        Map<String, Object> notification = new HashMap<>();
        notification.put("userId", user.getId());
        notification.put("email", user.getEmail());
        notification.put("type", "MFA_ENABLED");
        notification.put("subject", "Two-Factor Authentication Enabled");
        notification.put("template", "mfa-enabled");
        notification.put("data", Map.of(
                "username", user.getUsername() != null ? user.getUsername() : user.getEmail(),
                "mfaType", mfaType,
                "enabledAt", System.currentTimeMillis()
        ));

        sendNotification(notification);
    }

    /**
     * Send suspicious activity alert.
     */
    @CircuitBreaker(name = "notification-service", fallbackMethod = "fallbackNotification")
    @Retry(name = "notification-service")
    public void sendSuspiciousActivityAlert(User user, String activity, String ipAddress) {
        log.warn("Sending suspicious activity alert for user: {}", user.getId());

        Map<String, Object> notification = new HashMap<>();
        notification.put("userId", user.getId());
        notification.put("email", user.getEmail());
        notification.put("type", "SECURITY_ALERT");
        notification.put("subject", "Security Alert: Suspicious Activity Detected");
        notification.put("template", "security-alert");
        notification.put("priority", "HIGH");
        notification.put("data", Map.of(
                "username", user.getUsername() != null ? user.getUsername() : user.getEmail(),
                "activity", activity,
                "ipAddress", ipAddress,
                "timestamp", System.currentTimeMillis(),
                "action", "Please review your account activity and change your password if you don't recognize this activity."
        ));

        sendNotification(notification);
    }

    /**
     * Send login from new device notification.
     */
    @CircuitBreaker(name = "notification-service", fallbackMethod = "fallbackNotification")
    @Retry(name = "notification-service")
    public void sendNewDeviceLoginNotification(User user, String deviceInfo, String ipAddress) {
        log.info("Sending new device login notification for user: {}", user.getId());

        Map<String, Object> notification = new HashMap<>();
        notification.put("userId", user.getId());
        notification.put("email", user.getEmail());
        notification.put("type", "NEW_DEVICE_LOGIN");
        notification.put("subject", "New Device Login Detected");
        notification.put("template", "new-device-login");
        notification.put("data", Map.of(
                "username", user.getUsername() != null ? user.getUsername() : user.getEmail(),
                "deviceInfo", deviceInfo,
                "ipAddress", ipAddress,
                "loginTime", System.currentTimeMillis()
        ));

        sendNotification(notification);
    }

    // Private helper methods

    private void sendNotification(Map<String, Object> notification) {
        try {
            String url = notificationServiceUrl + "/api/v1/notifications/send";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(notification, headers);

            restTemplate.postForEntity(url, request, Void.class);

            log.debug("Notification sent successfully: {}", notification.get("type"));
        } catch (Exception e) {
            log.error("Failed to send notification: {}", e.getMessage());
            throw new RuntimeException("Notification service unavailable", e);
        }
    }

    // Fallback methods for circuit breaker

    public void fallbackNotification(User user, Exception e) {
        log.error("Notification service unavailable, fallback activated: {}", e.getMessage());
        // Could implement alternative notification mechanism here
        // For example, write to a queue for later processing
    }

    public void fallbackNotification(User user, String param, Exception e) {
        log.error("Notification service unavailable, fallback activated: {}", e.getMessage());
    }

    public void fallbackNotification(User user, String param1, String param2, Exception e) {
        log.error("Notification service unavailable, fallback activated: {}", e.getMessage());
    }
}