package com.nnipa.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Service for managing user sessions with Redis.
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
     * Create a new session.
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
     * Invalidate a session.
     */
    public void invalidateSession(String sessionId) {
        String sessionKey = SESSION_PREFIX + sessionId;
        redisTemplate.delete(sessionKey);
        log.debug("Invalidated session {}", sessionId);
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