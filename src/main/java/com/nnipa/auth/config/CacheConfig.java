package com.nnipa.auth.config;

import org.springframework.cache.CacheManager;
import org.springframework.cache.interceptor.KeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Cache configuration for the Authentication Service.
 * Uses Redis for distributed caching across service instances.
 */
@Configuration
public class CacheConfig {

    /**
     * Custom cache manager with different TTLs for different cache types.
     */
    @Bean
    public CacheManager cacheManager(RedisConnectionFactory connectionFactory) {
        RedisCacheConfiguration defaultConfig = RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(10))
                .serializeKeysWith(RedisSerializationContext.SerializationPair
                        .fromSerializer(new StringRedisSerializer()))
                .serializeValuesWith(RedisSerializationContext.SerializationPair
                        .fromSerializer(new GenericJackson2JsonRedisSerializer()))
                .disableCachingNullValues();

        Map<String, RedisCacheConfiguration> cacheConfigurations = new HashMap<>();

        // User authentication cache - short TTL for security
        cacheConfigurations.put("userAuth", defaultConfig.entryTtl(Duration.ofMinutes(5)));

        // OAuth state cache - medium TTL for OAuth flow
        cacheConfigurations.put("oauthState", defaultConfig.entryTtl(Duration.ofMinutes(10)));

        // MFA tokens cache - very short TTL for security
        cacheConfigurations.put("mfaTokens", defaultConfig.entryTtl(Duration.ofMinutes(2)));

        // Password reset tokens - medium TTL
        cacheConfigurations.put("passwordResetTokens", defaultConfig.entryTtl(Duration.ofMinutes(15)));

        // Failed login attempts - longer TTL for rate limiting
        cacheConfigurations.put("failedLoginAttempts", defaultConfig.entryTtl(Duration.ofMinutes(30)));

        // Session cache - configurable based on session timeout
        cacheConfigurations.put("sessions", defaultConfig.entryTtl(Duration.ofMinutes(30)));

        // JWT blacklist - should match JWT expiration time
        cacheConfigurations.put("jwtBlacklist", defaultConfig.entryTtl(Duration.ofHours(24)));

        return RedisCacheManager.builder(connectionFactory)
                .cacheDefaults(defaultConfig)
                .withInitialCacheConfigurations(cacheConfigurations)
                .transactionAware()
                .build();
    }

    /**
     * Custom key generator for complex cache keys.
     */
    @Bean("customKeyGenerator")
    public KeyGenerator keyGenerator() {
        return (target, method, params) -> {
            StringBuilder sb = new StringBuilder();
            sb.append(target.getClass().getSimpleName());
            sb.append(".");
            sb.append(method.getName());
            for (Object param : params) {
                sb.append(".");
                sb.append(param != null ? param.toString() : "null");
            }
            return sb.toString();
        };
    }
}