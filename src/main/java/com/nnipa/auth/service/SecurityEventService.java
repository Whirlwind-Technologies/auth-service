package com.nnipa.auth.service;

import com.nnipa.auth.enums.SecurityEventType;
import com.nnipa.proto.auth.SecurityEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Service for detecting and logging security events
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityEventService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final KafkaTemplate<String, byte[]> kafkaTemplate;

    private static final String ACTIVITY_PREFIX = "security:activity:";
    private static final String SUSPICIOUS_PREFIX = "security:suspicious:";
    private static final String FAILED_ATTEMPTS_PREFIX = "security:failed:";
    private static final String SECURITY_EVENTS_TOPIC = "nnipa.events.security";

    // Thresholds for suspicious activity detection
    private static final int MAX_IPS_PER_DAY = 3;
    private static final int MAX_USER_AGENTS_PER_DAY = 5;
    private static final int SUSPICIOUS_LOGIN_THRESHOLD = 3;
    private static final long IMPOSSIBLE_TRAVEL_TIME_MINUTES = 30;

    public boolean detectSuspiciousActivity(UUID userId, String ipAddress, String userAgent) {
        String activityKey = ACTIVITY_PREFIX + userId;

        // Get recent activity
        Set<Object> recentIps = redisTemplate.opsForSet().members(activityKey + ":ips");
        Set<Object> recentAgents = redisTemplate.opsForSet().members(activityKey + ":agents");

        boolean suspicious = false;
        List<String> suspiciousReasons = new ArrayList<>();

        // Check for new IP address
        if (recentIps != null && !recentIps.isEmpty() && !recentIps.contains(ipAddress)) {
            if (recentIps.size() >= MAX_IPS_PER_DAY) {
                suspicious = true;
                suspiciousReasons.add("multiple_ips");
                log.warn("Suspicious activity: Multiple IPs ({}) for user {}", recentIps.size(), userId);
            }
        }

        // Check for unusual user agent
        if (recentAgents != null && !recentAgents.isEmpty() && !recentAgents.contains(userAgent)) {
            if (recentAgents.size() >= MAX_USER_AGENTS_PER_DAY) {
                suspicious = true;
                suspiciousReasons.add("multiple_user_agents");
                log.warn("Suspicious activity: Multiple user agents ({}) for user {}", recentAgents.size(), userId);
            }
        }

        // Check for impossible travel
        if (ipAddress != null && recentIps != null && !recentIps.isEmpty()) {
            if (checkImpossibleTravel(userId, ipAddress, recentIps)) {
                suspicious = true;
                suspiciousReasons.add("impossible_travel");
            }
        }

        // Check login frequency
        if (checkHighFrequencyLogins(userId)) {
            suspicious = true;
            suspiciousReasons.add("high_frequency_logins");
        }

        // Record current activity
        recordActivity(userId, ipAddress, userAgent);

        if (suspicious) {
            recordSuspiciousActivity(userId, ipAddress, userAgent, suspiciousReasons);
        }

        return suspicious;
    }

    private void recordActivity(UUID userId, String ipAddress, String userAgent) {
        String activityKey = ACTIVITY_PREFIX + userId;

        // Record IP addresses
        if (ipAddress != null) {
            redisTemplate.opsForSet().add(activityKey + ":ips", ipAddress);
            redisTemplate.expire(activityKey + ":ips", 24, TimeUnit.HOURS);
        }

        // Record user agents
        if (userAgent != null) {
            redisTemplate.opsForSet().add(activityKey + ":agents", userAgent);
            redisTemplate.expire(activityKey + ":agents", 24, TimeUnit.HOURS);
        }

        // Record timestamp with location info
        String timelineEntry = String.format("%s|%s|%d",
                ipAddress != null ? ipAddress : "unknown",
                userAgent != null ? userAgent.substring(0, Math.min(50, userAgent.length())) : "unknown",
                System.currentTimeMillis()
        );

        redisTemplate.opsForZSet().add(
                activityKey + ":timeline",
                timelineEntry,
                System.currentTimeMillis()
        );
        redisTemplate.expire(activityKey + ":timeline", 7, TimeUnit.DAYS);

        // Increment login counter for frequency analysis
        String loginCountKey = activityKey + ":login_count:" + LocalDateTime.now().toLocalDate();
        redisTemplate.opsForValue().increment(loginCountKey);
        redisTemplate.expire(loginCountKey, 1, TimeUnit.DAYS);
    }

    private void recordSuspiciousActivity(UUID userId, String ipAddress, String userAgent, List<String> reasons) {
        String suspiciousKey = SUSPICIOUS_PREFIX + userId;

        Map<String, Object> activity = Map.of(
                "user_id", userId.toString(),
                "ip_address", ipAddress != null ? ipAddress : "unknown",
                "user_agent", userAgent != null ? userAgent : "unknown",
                "timestamp", System.currentTimeMillis(),
                "type", "SUSPICIOUS_LOGIN",
                "reasons", String.join(",", reasons),
                "risk_score", calculateRiskScore(reasons)
        );

        redisTemplate.opsForList().leftPush(suspiciousKey, activity);
        redisTemplate.expire(suspiciousKey, 30, TimeUnit.DAYS);

        // Increment suspicious activity counter
        String suspiciousCountKey = SUSPICIOUS_PREFIX + "count:" + userId + ":" + LocalDateTime.now().toLocalDate();
        redisTemplate.opsForValue().increment(suspiciousCountKey);
        redisTemplate.expire(suspiciousCountKey, 7, TimeUnit.DAYS);

        // Publish security event
        publishSecurityEvent(activity);

        log.warn("Suspicious activity recorded for user {}: {} [Risk Score: {}]",
                userId, reasons, activity.get("risk_score"));
    }

    private boolean checkImpossibleTravel(UUID userId, String currentIp, Set<Object> recentIps) {
        try {
            String timelineKey = ACTIVITY_PREFIX + userId + ":timeline";

            // Get recent timeline entries (last 30 minutes)
            long thirtyMinutesAgo = System.currentTimeMillis() - (IMPOSSIBLE_TRAVEL_TIME_MINUTES * 60 * 1000);
            Set<Object> recentEntries = redisTemplate.opsForZSet()
                    .rangeByScore(timelineKey, thirtyMinutesAgo, System.currentTimeMillis());

            if (recentEntries == null || recentEntries.isEmpty()) {
                return false;
            }

            // Check if current IP is different from recent IPs in timeline
            for (Object entry : recentEntries) {
                String entryStr = entry.toString();
                String[] parts = entryStr.split("\\|");
                if (parts.length >= 1) {
                    String recentIp = parts[0];
                    if (!recentIp.equals(currentIp) && !recentIp.equals("unknown")) {
                        // In production, you would use GeoIP service to calculate distance
                        // For now, check if IPs are from different subnets
                        if (isDifferentSubnet(currentIp, recentIp)) {
                            log.warn("Possible impossible travel detected for user {}: {} -> {}",
                                    userId, recentIp, currentIp);
                            return true;
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error checking impossible travel for user {}", userId, e);
        }

        return false;
    }

    private boolean isDifferentSubnet(String ip1, String ip2) {
        try {
            // Simple subnet check - compare first 3 octets
            String[] parts1 = ip1.split("\\.");
            String[] parts2 = ip2.split("\\.");

            if (parts1.length >= 3 && parts2.length >= 3) {
                return !parts1[0].equals(parts2[0]) ||
                        !parts1[1].equals(parts2[1]) ||
                        !parts1[2].equals(parts2[2]);
            }
        } catch (Exception e) {
            log.debug("Error comparing subnets for IPs {} and {}", ip1, ip2);
        }
        return false;
    }

    private boolean checkHighFrequencyLogins(UUID userId) {
        try {
            String loginCountKey = ACTIVITY_PREFIX + userId + ":login_count:" + LocalDateTime.now().toLocalDate();
            Object count = redisTemplate.opsForValue().get(loginCountKey);

            if (count != null) {
                int loginCount = Integer.parseInt(count.toString());
                if (loginCount >= SUSPICIOUS_LOGIN_THRESHOLD) {
                    log.warn("High frequency logins detected for user {}: {} logins today", userId, loginCount);
                    return true;
                }
            }
        } catch (Exception e) {
            log.error("Error checking login frequency for user {}", userId, e);
        }

        return false;
    }

    private int calculateRiskScore(List<String> reasons) {
        int score = 0;
        for (String reason : reasons) {
            switch (reason) {
                case "impossible_travel":
                    score += 50;
                    break;
                case "multiple_ips":
                    score += 30;
                    break;
                case "multiple_user_agents":
                    score += 20;
                    break;
                case "high_frequency_logins":
                    score += 25;
                    break;
                default:
                    score += 10;
            }
        }
        return Math.min(score, 100); // Cap at 100
    }

    public void logEvent(SecurityEventType eventType, String username, String ipAddress, String correlationId) {
        Map<String, Object> event = Map.of(
                "event_id", UUID.randomUUID().toString(),
                "event_type", eventType.toString(),
                "username", username != null ? username : "unknown",
                "ip_address", ipAddress != null ? ipAddress : "unknown",
                "correlation_id", correlationId != null ? correlationId : UUID.randomUUID().toString(),
                "timestamp", System.currentTimeMillis(),
                "severity", getEventSeverity(eventType),
                "description", getEventDescription(eventType)
        );

        // Store in Redis for analysis
        String eventKey = "security:events:" + LocalDateTime.now().toLocalDate();
        redisTemplate.opsForList().leftPush(eventKey, event);
        redisTemplate.expire(eventKey, 90, TimeUnit.DAYS);

        // Store by event type for trend analysis
        String typeKey = "security:events:by_type:" + eventType + ":" + LocalDateTime.now().toLocalDate();
        redisTemplate.opsForValue().increment(typeKey);
        redisTemplate.expire(typeKey, 30, TimeUnit.DAYS);

        // Store by IP for threat analysis
        if (ipAddress != null) {
            String ipKey = "security:events:by_ip:" + ipAddress + ":" + LocalDateTime.now().toLocalDate();
            redisTemplate.opsForValue().increment(ipKey);
            redisTemplate.expire(ipKey, 30, TimeUnit.DAYS);
        }

        // Publish to Kafka for real-time processing
        publishSecurityEvent(event);

        log.info("Security event logged: {} for user: {} from IP: {} [Correlation-ID: {}]",
                eventType, username, ipAddress, correlationId);

        // Check if this triggers any alerts
        checkForSecurityAlerts(eventType, username, ipAddress);
    }

    private void publishSecurityEvent(Map<String, Object> eventData) {
        try {
            // Option 1: Use SecurityEvent proto (uncomment when proto is compiled)
            /*
            SecurityEvent.Builder eventBuilder = SecurityEvent.newBuilder()
                .setEventId(eventData.get("event_id") != null ? eventData.get("event_id").toString() : UUID.randomUUID().toString())
                .setEventType(eventData.get("event_type").toString())
                .setTimestamp(Long.parseLong(eventData.get("timestamp").toString()));

            if (eventData.containsKey("user_id")) {
                eventBuilder.setUserId(eventData.get("user_id").toString());
            }
            if (eventData.containsKey("username")) {
                eventBuilder.setUsername(eventData.get("username").toString());
            }
            if (eventData.containsKey("ip_address")) {
                eventBuilder.setIpAddress(eventData.get("ip_address").toString());
            }
            if (eventData.containsKey("correlation_id")) {
                eventBuilder.setCorrelationId(eventData.get("correlation_id").toString());
            }
            if (eventData.containsKey("severity")) {
                eventBuilder.setSeverity(eventData.get("severity").toString());
            }
            if (eventData.containsKey("risk_score")) {
                eventBuilder.setRiskScore(Integer.parseInt(eventData.get("risk_score").toString()));
            }
            if (eventData.containsKey("description")) {
                eventBuilder.setDescription(eventData.get("description").toString());
            }

            SecurityEvent event = eventBuilder.build();
            kafkaTemplate.send(SECURITY_EVENTS_TOPIC,
                eventData.get("correlation_id") != null ? eventData.get("correlation_id").toString() : UUID.randomUUID().toString(),
                event.toByteArray());
            */

            // Option 2: Use JSON serialization as fallback (current implementation)
            String eventJson = convertEventDataToJson(eventData);
            kafkaTemplate.send(SECURITY_EVENTS_TOPIC,
                    eventData.get("correlation_id") != null ? eventData.get("correlation_id").toString() : UUID.randomUUID().toString(),
                    eventJson.getBytes());

            log.debug("Security event published to Kafka: {}", eventData.get("event_type"));
        } catch (Exception e) {
            log.error("Failed to publish security event to Kafka", e);
        }
    }

    private String convertEventDataToJson(Map<String, Object> eventData) {
        try {
            // Simple JSON conversion - in production you'd use Jackson ObjectMapper
            StringBuilder json = new StringBuilder();
            json.append("{");
            boolean first = true;
            for (Map.Entry<String, Object> entry : eventData.entrySet()) {
                if (!first) json.append(",");
                json.append("\"").append(entry.getKey()).append("\":");

                Object value = entry.getValue();
                if (value instanceof String) {
                    json.append("\"").append(value.toString().replace("\"", "\\\"")).append("\"");
                } else if (value instanceof Number) {
                    json.append(value.toString());
                } else if (value instanceof Boolean) {
                    json.append(value.toString());
                } else {
                    json.append("\"").append(value != null ? value.toString().replace("\"", "\\\"") : "null").append("\"");
                }
                first = false;
            }
            json.append("}");
            return json.toString();
        } catch (Exception e) {
            log.error("Error converting event data to JSON", e);
            return "{}";
        }
    }

    private String getEventSeverity(SecurityEventType eventType) {
        switch (eventType) {
            case ACCOUNT_LOCKED:
            case SUSPICIOUS_LOGIN:
            case PASSWORD_EXPIRED:
                return "HIGH";
            case INVALID_CREDENTIALS:
            case SUSPENDED_ACCOUNT_ACCESS:
                return "MEDIUM";
            default:
                return "LOW";
        }
    }

    private String getEventDescription(SecurityEventType eventType) {
        switch (eventType) {
            case BRUTE_FORCE_ATTACK:
                return "Brute force attack pattern detected";
            case SUSPICIOUS_ACTIVITY:
                return "Suspicious user activity detected";
            case ACCOUNT_TAKEOVER_ATTEMPT:
                return "Potential account takeover attempt";
            case INVALID_TOKEN_USE:
                return "Invalid or tampered token usage detected";
            case CONCURRENT_SESSION_LIMIT:
                return "Exceeded maximum concurrent session limit";
            case GEO_LOCATION_ANOMALY:
                return "Login from unusual geographic location";
            case UNUSUAL_ACCESS_PATTERN:
                return "Unusual access pattern detected";
            case DATA_BREACH_ATTEMPT:
                return "Potential data breach attempt detected";
            case PRIVILEGE_ESCALATION_ATTEMPT:
                return "Attempt to escalate user privileges";
            case MFA_BYPASS_ATTEMPT:
                return "Attempt to bypass multi-factor authentication";
            case ACCOUNT_LOCKED:
                return "Account locked due to security policy";
            case INVALID_CREDENTIALS:
                return "Login attempt with invalid credentials";
            case SUSPENDED_ACCOUNT_ACCESS:
                return "Access attempt on suspended account";
            case PASSWORD_EXPIRED:
                return "Login attempt with expired password";
            case SUSPICIOUS_LOGIN:
                return "Login flagged as suspicious";
            default:
                return "Security event occurred";
        }
    }

    private void checkForSecurityAlerts(SecurityEventType eventType, String username, String ipAddress) {
        try {
            // Check for patterns that should trigger immediate alerts
            if (eventType == SecurityEventType.SUSPICIOUS_LOGIN) {
                checkSuspiciousLoginPatterns(username, ipAddress);
            }

            if (eventType == SecurityEventType.INVALID_CREDENTIALS) {
                checkBruteForcePatterns(username, ipAddress);
            }
        } catch (Exception e) {
            log.error("Error checking security alert patterns", e);
        }
    }

    private void checkSuspiciousLoginPatterns(String username, String ipAddress) {
        // Check if there have been multiple suspicious logins in the last hour
        String alertKey = "security:alerts:suspicious:" + username;
        Long count = redisTemplate.opsForValue().increment(alertKey);
        redisTemplate.expire(alertKey, 1, TimeUnit.HOURS);

        if (count != null && count >= 3) {
            triggerSecurityAlert("MULTIPLE_SUSPICIOUS_LOGINS", username, ipAddress,
                    "Multiple suspicious login attempts detected");
        }
    }

    private void checkBruteForcePatterns(String username, String ipAddress) {
        // Check for brute force patterns by IP
        if (ipAddress != null) {
            String ipFailureKey = FAILED_ATTEMPTS_PREFIX + "ip:" + ipAddress;
            Long ipFailures = redisTemplate.opsForValue().increment(ipFailureKey);
            redisTemplate.expire(ipFailureKey, 1, TimeUnit.HOURS);

            if (ipFailures != null && ipFailures >= 20) {
                triggerSecurityAlert("BRUTE_FORCE_IP", username, ipAddress,
                        "Potential brute force attack from IP address");
            }
        }
    }

    private void triggerSecurityAlert(String alertType, String username, String ipAddress, String description) {
        Map<String, Object> alert = Map.of(
                "alert_id", UUID.randomUUID().toString(),
                "alert_type", alertType,
                "username", username != null ? username : "unknown",
                "ip_address", ipAddress != null ? ipAddress : "unknown",
                "description", description,
                "timestamp", System.currentTimeMillis(),
                "severity", "CRITICAL"
        );

        // Store alert
        String alertKey = "security:alerts:" + LocalDateTime.now().toLocalDate();
        redisTemplate.opsForList().leftPush(alertKey, alert);
        redisTemplate.expire(alertKey, 30, TimeUnit.DAYS);

        // Publish alert event
        publishSecurityEvent(alert);

        log.error("SECURITY ALERT: {} - {} [User: {}, IP: {}]",
                alertType, description, username, ipAddress);
    }

    /**
     * Get security events for analysis
     */
    public List<Map<String, Object>> getSecurityEvents(LocalDateTime from, LocalDateTime to, SecurityEventType eventType) {
        List<Map<String, Object>> events = new ArrayList<>();

        try {
            LocalDateTime current = from.toLocalDate().atStartOfDay();
            while (!current.toLocalDate().isAfter(to.toLocalDate())) {
                String eventKey = "security:events:" + current.toLocalDate();
                List<Object> dailyEvents = redisTemplate.opsForList().range(eventKey, 0, -1);

                if (dailyEvents != null) {
                    events.addAll(dailyEvents.stream()
                            .map(event -> (Map<String, Object>) event)
                            .filter(event -> eventType == null ||
                                    eventType.toString().equals(event.get("event_type")))
                            .collect(Collectors.toList()));
                }

                current = current.plusDays(1);
            }
        } catch (Exception e) {
            log.error("Error retrieving security events", e);
        }

        return events;
    }

    /**
     * Get user activity timeline
     */
    public List<Map<String, Object>> getUserActivityTimeline(UUID userId, int hours) {
        List<Map<String, Object>> timeline = new ArrayList<>();

        try {
            String timelineKey = ACTIVITY_PREFIX + userId + ":timeline";
            long fromTime = System.currentTimeMillis() - (hours * 60 * 60 * 1000L);

            Set<Object> entries = redisTemplate.opsForZSet()
                    .rangeByScore(timelineKey, fromTime, System.currentTimeMillis());

            if (entries != null) {
                for (Object entry : entries) {
                    String[] parts = entry.toString().split("\\|");
                    if (parts.length >= 3) {
                        timeline.add(Map.of(
                                "ip_address", parts[0],
                                "user_agent", parts[1],
                                "timestamp", Long.parseLong(parts[2])
                        ));
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error retrieving user activity timeline for user {}", userId, e);
        }

        return timeline;
    }
}