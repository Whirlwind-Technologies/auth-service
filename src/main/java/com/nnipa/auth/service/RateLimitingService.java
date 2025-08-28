package com.nnipa.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Service for rate limiting login attempts.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RateLimitingService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String ATTEMPT_PREFIX = "login-attempt:";
    private static final String BLOCK_PREFIX = "login-block:";
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration BLOCK_DURATION = Duration.ofMinutes(15);
    private static final Duration ATTEMPT_WINDOW = Duration.ofMinutes(15);

    /**
     * Record a failed login attempt.
     */
    public void recordFailedAttempt(String identifier, String ipAddress) {
        String attemptKey = ATTEMPT_PREFIX + identifier;
        String ipAttemptKey = ATTEMPT_PREFIX + "ip:" + ipAddress;

        Long attempts = redisTemplate.opsForValue().increment(attemptKey);
        redisTemplate.expire(attemptKey, ATTEMPT_WINDOW);

        Long ipAttempts = redisTemplate.opsForValue().increment(ipAttemptKey);
        redisTemplate.expire(ipAttemptKey, ATTEMPT_WINDOW);

        // Block if exceeded max attempts
        if (attempts != null && attempts >= MAX_ATTEMPTS) {
            blockLogin(identifier);
        }

        if (ipAttempts != null && ipAttempts >= MAX_ATTEMPTS * 2) {
            blockLogin("ip:" + ipAddress);
        }

        log.debug("Failed attempt #{} for {}", attempts, identifier);
    }

    /**
     * Reset failed attempts after successful login.
     */
    public void resetFailedAttempts(String identifier) {
        String attemptKey = ATTEMPT_PREFIX + identifier;
        redisTemplate.delete(attemptKey);
        log.debug("Reset failed attempts for {}", identifier);
    }

    /**
     * Check if login is blocked.
     */
    public boolean isLoginBlocked(String identifier, String ipAddress) {
        String blockKey = BLOCK_PREFIX + identifier;
        String ipBlockKey = BLOCK_PREFIX + "ip:" + ipAddress;

        return Boolean.TRUE.equals(redisTemplate.hasKey(blockKey)) ||
                Boolean.TRUE.equals(redisTemplate.hasKey(ipBlockKey));
    }

    /**
     * Block login attempts.
     */
    private void blockLogin(String identifier) {
        String blockKey = BLOCK_PREFIX + identifier;
        redisTemplate.opsForValue().set(blockKey, true, BLOCK_DURATION);
        log.warn("Blocked login attempts for {}", identifier);
    }

    /**
     * Get remaining block time in seconds.
     */
    public Long getRemainingBlockTime(String identifier) {
        String blockKey = BLOCK_PREFIX + identifier;
        return redisTemplate.getExpire(blockKey, TimeUnit.SECONDS);
    }
}