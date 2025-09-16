package com.nnipa.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.TimeUnit; /**
 * Service for managing account lockouts
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccountLockoutService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String LOCKOUT_PREFIX = "account-lockout:";
    private static final String ATTEMPT_PREFIX = "lockout-attempt:";
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(30);
    private static final Duration ATTEMPT_WINDOW = Duration.ofMinutes(15);

    public boolean isAccountLocked(String username) {
        String lockoutKey = LOCKOUT_PREFIX + username;
        return Boolean.TRUE.equals(redisTemplate.hasKey(lockoutKey));
    }

    public void recordFailedAttempt(String username) {
        String attemptKey = ATTEMPT_PREFIX + username;

        Long attempts = redisTemplate.opsForValue().increment(attemptKey);
        redisTemplate.expire(attemptKey, ATTEMPT_WINDOW);

        if (attempts != null && attempts >= MAX_ATTEMPTS) {
            lockAccount(username);
        }

        log.debug("Failed attempt #{} for user: {}", attempts, username);
    }

    public void resetFailedAttempts(String username) {
        String attemptKey = ATTEMPT_PREFIX + username;
        redisTemplate.delete(attemptKey);
        log.debug("Reset failed attempts for user: {}", username);
    }

    private void lockAccount(String username) {
        String lockoutKey = LOCKOUT_PREFIX + username;
        redisTemplate.opsForValue().set(lockoutKey, true, LOCKOUT_DURATION);
        log.warn("Account locked for user: {}", username);

        // Send notification about account lockout
        publishAccountLockoutEvent(username);
    }

    public void unlockAccount(String username) {
        String lockoutKey = LOCKOUT_PREFIX + username;
        String attemptKey = ATTEMPT_PREFIX + username;

        redisTemplate.delete(lockoutKey);
        redisTemplate.delete(attemptKey);

        log.info("Account unlocked for user: {}", username);
    }

    public Long getRemainingLockoutTime(String username) {
        String lockoutKey = LOCKOUT_PREFIX + username;
        return redisTemplate.getExpire(lockoutKey, TimeUnit.SECONDS);
    }

    private void publishAccountLockoutEvent(String username) {
        // Publish event to notification service
        Map<String, Object> event = Map.of(
                "event_type", "ACCOUNT_LOCKED",
                "username", username,
                "locked_at", LocalDateTime.now().toString(),
                "unlock_at", LocalDateTime.now().plus(LOCKOUT_DURATION).toString()
        );

        // This would publish to Kafka in production
        log.info("Account lockout event published for user: {}", username);
    }
}
