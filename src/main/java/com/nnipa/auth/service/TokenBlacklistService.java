package com.nnipa.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit; /**
 * Service for managing token blacklist
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String BLACKLIST_PREFIX = "blacklist:token:";

    public void blacklistToken(String token) {
        // Extract expiration from token
        long ttl = extractTokenTTL(token);

        String key = BLACKLIST_PREFIX + token;
        redisTemplate.opsForValue().set(key, true, ttl, TimeUnit.SECONDS);

        log.info("Token blacklisted: {}", token.substring(0, 10) + "...");
    }

    public boolean isTokenBlacklisted(String token) {
        String key = BLACKLIST_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    public void removeFromBlacklist(String token) {
        String key = BLACKLIST_PREFIX + token;
        redisTemplate.delete(key);
        log.info("Token removed from blacklist");
    }

    private long extractTokenTTL(String token) {
        // Extract TTL from JWT token
        // In production, this would decode the token and get the exp claim
        return 3600; // Default 1 hour
    }
}
