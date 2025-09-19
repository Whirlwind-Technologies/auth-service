package com.nnipa.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Service to track temporary tenant IDs created when synchronous calls fail.
 * Uses Redis with TTL to automatically clean up old entries.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TemporaryTenantTracker {

    private static final String TEMP_TENANT_KEY_PREFIX = "temp:tenant:";
    private static final String USER_TENANT_MAPPING_PREFIX = "user:tenant:temp:";
    private static final Duration DEFAULT_TTL = Duration.ofHours(24);

    private final RedisTemplate<String, String> redisTemplate;

    /**
     * Register a temporary tenant ID for a user.
     *
     * @param userId The user ID
     * @param temporaryTenantId The temporary tenant ID assigned
     * @param correlationId The correlation ID for tracking
     * @return true if registered successfully
     */
    public boolean registerTemporaryTenant(UUID userId, UUID temporaryTenantId, String correlationId) {
        try {
            String tempTenantKey = TEMP_TENANT_KEY_PREFIX + temporaryTenantId.toString();
            String userMappingKey = USER_TENANT_MAPPING_PREFIX + userId.toString();

            // Store temporary tenant info
            redisTemplate.opsForHash().put(tempTenantKey, "userId", userId.toString());
            redisTemplate.opsForHash().put(tempTenantKey, "correlationId", correlationId);
            redisTemplate.opsForHash().put(tempTenantKey, "createdAt", String.valueOf(System.currentTimeMillis()));
            redisTemplate.expire(tempTenantKey, DEFAULT_TTL);

            // Store user -> temp tenant mapping
            redisTemplate.opsForValue().set(userMappingKey, temporaryTenantId.toString(), DEFAULT_TTL);

            log.debug("Registered temporary tenant {} for user {} with correlation ID: {}",
                    temporaryTenantId, userId, correlationId);

            return true;
        } catch (Exception e) {
            log.error("Failed to register temporary tenant", e);
            return false;
        }
    }

    /**
     * Check if a tenant ID is temporary.
     *
     * @param tenantId The tenant ID to check
     * @return true if the tenant ID is temporary
     */
    public boolean isTemporary(UUID tenantId) {
        try {
            String key = TEMP_TENANT_KEY_PREFIX + tenantId.toString();
            return Boolean.TRUE.equals(redisTemplate.hasKey(key));
        } catch (Exception e) {
            log.error("Failed to check if tenant ID is temporary", e);
            return false;
        }
    }

    /**
     * Get temporary tenant ID for a user.
     *
     * @param userId The user ID
     * @return The temporary tenant ID if exists, null otherwise
     */
    public UUID getTemporaryTenantForUser(UUID userId) {
        try {
            String key = USER_TENANT_MAPPING_PREFIX + userId.toString();
            String tempTenantId = redisTemplate.opsForValue().get(key);

            if (tempTenantId != null) {
                return UUID.fromString(tempTenantId);
            }
            return null;
        } catch (Exception e) {
            log.error("Failed to get temporary tenant for user", e);
            return null;
        }
    }

    /**
     * Remove temporary tenant ID after successful update.
     *
     * @param temporaryTenantId The temporary tenant ID to remove
     */
    public void removeTemporaryTenant(UUID temporaryTenantId) {
        try {
            String tempTenantKey = TEMP_TENANT_KEY_PREFIX + temporaryTenantId.toString();

            // Get user ID before deleting
            Object userId = redisTemplate.opsForHash().get(tempTenantKey, "userId");

            // Delete temporary tenant entry
            redisTemplate.delete(tempTenantKey);

            // Delete user mapping
            if (userId != null) {
                String userMappingKey = USER_TENANT_MAPPING_PREFIX + userId.toString();
                redisTemplate.delete(userMappingKey);
            }

            log.debug("Removed temporary tenant {} from tracking", temporaryTenantId);

        } catch (Exception e) {
            log.error("Failed to remove temporary tenant", e);
        }
    }

    /**
     * Get correlation ID for a temporary tenant.
     *
     * @param temporaryTenantId The temporary tenant ID
     * @return The correlation ID if found, null otherwise
     */
    public String getCorrelationId(UUID temporaryTenantId) {
        try {
            String key = TEMP_TENANT_KEY_PREFIX + temporaryTenantId.toString();
            Object correlationId = redisTemplate.opsForHash().get(key, "correlationId");
            return correlationId != null ? correlationId.toString() : null;
        } catch (Exception e) {
            log.error("Failed to get correlation ID for temporary tenant", e);
            return null;
        }
    }

    /**
     * Get all temporary tenant IDs that are older than specified duration.
     * Useful for monitoring and cleanup.
     *
     * @param olderThan Duration to check against
     * @return Set of temporary tenant IDs
     */
    public Set<UUID> getStaleTemporaryTenants(Duration olderThan) {
        try {
            Set<String> keys = redisTemplate.keys(TEMP_TENANT_KEY_PREFIX + "*");
            Set<UUID> staleTenants = new HashSet<>();

            if (keys != null) {
                long cutoffTime = System.currentTimeMillis() - olderThan.toMillis();

                for (String key : keys) {
                    Object createdAt = redisTemplate.opsForHash().get(key, "createdAt");
                    if (createdAt != null) {
                        long createdTime = Long.parseLong(createdAt.toString());
                        if (createdTime < cutoffTime) {
                            String tenantId = key.replace(TEMP_TENANT_KEY_PREFIX, "");
                            staleTenants.add(UUID.fromString(tenantId));
                        }
                    }
                }
            }

            return staleTenants;
        } catch (Exception e) {
            log.error("Failed to get stale temporary tenants", e);
            return new HashSet<>();
        }
    }
}