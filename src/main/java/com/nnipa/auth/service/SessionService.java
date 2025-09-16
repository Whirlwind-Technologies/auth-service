package com.nnipa.auth.service;

import com.nnipa.auth.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Session service - fixed version with proper method signatures
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SessionService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String SESSION_PREFIX = "session:";
    private static final String BLACKLIST_PREFIX = "blacklist:";
    private static final String USER_SESSIONS_PREFIX = "user-sessions:";

    /**
     * Create session - method signature to match AuthenticationService call
     */
    public void createSession(User user, String accessToken, String refreshToken,
                              String ipAddress, String userAgent, String correlationId) {

        String sessionId = UUID.randomUUID().toString();

        Map<String, Object> sessionData = new HashMap<>();
        sessionData.put("userId", user.getId().toString());
        sessionData.put("tenantId", user.getTenantId().toString());
        sessionData.put("username", user.getUsername());
        sessionData.put("email", user.getEmail());
        sessionData.put("accessToken", accessToken);
        sessionData.put("refreshToken", refreshToken);
        sessionData.put("ipAddress", ipAddress);
        sessionData.put("userAgent", userAgent);
        sessionData.put("correlationId", correlationId);
        sessionData.put("createdAt", LocalDateTime.now().toString());
        sessionData.put("lastAccessedAt", LocalDateTime.now().toString());

        Duration ttl = Duration.ofHours(24); // Default session TTL

        String sessionKey = SESSION_PREFIX + sessionId;
        String userSessionKey = USER_SESSIONS_PREFIX + user.getId();

        redisTemplate.opsForValue().set(sessionKey, sessionData, ttl);
        redisTemplate.opsForSet().add(userSessionKey, sessionId);
        redisTemplate.expire(userSessionKey, ttl);

        log.debug("Created session {} for user {} with correlation ID: {}",
                sessionId, user.getId(), correlationId);
    }

    /**
     * Create a new session with custom TTL.
     */
    public void createSession(UUID userId, String sessionId, Object sessionData, Duration ttl) {
        String sessionKey = SESSION_PREFIX + sessionId;
        String userSessionKey = USER_SESSIONS_PREFIX + userId;

        redisTemplate.opsForValue().set(sessionKey, sessionData, ttl);
        redisTemplate.opsForSet().add(userSessionKey, sessionId);
        redisTemplate.expire(userSessionKey, ttl);

        log.debug("Created session {} for user {}", sessionId, userId);
    }

    /**
     * Get session data.
     */
    public Object getSession(String sessionId) {
        String sessionKey = SESSION_PREFIX + sessionId;
        return redisTemplate.opsForValue().get(sessionKey);
    }

    /**
     * Invalidate a session by session ID.
     */
    public void invalidateSession(String sessionId) {
        String sessionKey = SESSION_PREFIX + sessionId;
        redisTemplate.delete(sessionKey);
        log.debug("Invalidated session {}", sessionId);
    }

    /**
     * Invalidate session by user ID (method needed by AuthenticationService).
     */
    public void invalidateSession(UUID userId) {
        invalidateAllUserSessions(userId);
    }

    /**
     * Invalidate all user sessions.
     */
    public void invalidateAllUserSessions(UUID userId) {
        String userSessionKey = USER_SESSIONS_PREFIX + userId;
        Set<Object> sessions = redisTemplate.opsForSet().members(userSessionKey);

        if (sessions != null) {
            for (Object sessionId : sessions) {
                invalidateSession(sessionId.toString());
            }
        }

        redisTemplate.delete(userSessionKey);
        log.info("Invalidated all sessions for user {}", userId);
    }

    /**
     * Add token to blacklist.
     */
    public void blacklistToken(String jti, long expirationTime) {
        String blacklistKey = BLACKLIST_PREFIX + jti;
        redisTemplate.opsForValue().set(blacklistKey, true, expirationTime, TimeUnit.SECONDS);
        log.debug("Blacklisted token with JTI: {}", jti);
    }

    /**
     * Check if token is blacklisted.
     */
    public boolean isTokenBlacklisted(String jti) {
        String blacklistKey = BLACKLIST_PREFIX + jti;
        return Boolean.TRUE.equals(redisTemplate.hasKey(blacklistKey));
    }

    /**
     * Create remember-me session.
     */
    public void createRememberMeSession(UUID userId, String token) {
        String rememberMeKey = "remember-me:" + token;
        redisTemplate.opsForValue().set(rememberMeKey, userId, Duration.ofDays(14));
        log.debug("Created remember-me session for user {}", userId);
    }

    /**
     * Get user ID from remember-me token.
     */
    public UUID getUserIdFromRememberMeToken(String token) {
        String rememberMeKey = "remember-me:" + token;
        Object userId = redisTemplate.opsForValue().get(rememberMeKey);
        return userId != null ? UUID.fromString(userId.toString()) : null;
    }
}