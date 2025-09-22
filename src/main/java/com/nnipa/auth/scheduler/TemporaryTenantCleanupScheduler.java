package com.nnipa.auth.scheduler;

import com.nnipa.auth.service.TemporaryTenantTracker;
import com.nnipa.auth.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

/**
 * Scheduled task to monitor and clean up stale temporary tenant associations.
 * Runs periodically to ensure no users are stuck with temporary tenant IDs.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TemporaryTenantCleanupScheduler {

    private final TemporaryTenantTracker temporaryTenantTracker;
    private final UserRepository userRepository;

    @Value("${tenant.cleanup.stale-duration:PT1H}")
    private Duration staleDuration;  // Default 1 hour

    @Value("${tenant.cleanup.enabled:true}")
    private boolean cleanupEnabled;

    /**
     * Run every 30 minutes to check for stale temporary tenants.
     */
    @Scheduled(fixedDelayString = "${tenant.cleanup.interval:PT30M}")
    public void cleanupStaleTenants() {
        if (!cleanupEnabled) {
            log.debug("Temporary tenant cleanup is disabled");
            return;
        }

        try {
            log.info("Starting temporary tenant cleanup task");

            // Get temporary tenants older than configured duration
            Set<UUID> staleTenants = temporaryTenantTracker.getStaleTemporaryTenants(staleDuration);

            if (staleTenants.isEmpty()) {
                log.debug("No stale temporary tenants found");
                return;
            }

            log.warn("Found {} stale temporary tenant IDs", staleTenants.size());

            for (UUID tempTenantId : staleTenants) {
                handleStaleTenant(tempTenantId);
            }

            log.info("Completed temporary tenant cleanup task");

        } catch (Exception e) {
            log.error("Error during temporary tenant cleanup", e);
        }
    }

    /**
     * Handle a stale temporary tenant.
     */
    @Transactional
    protected void handleStaleTenant(UUID tempTenantId) {
        try {
            //// Find users with this temporary tenant ID. Use eager-fetching query
            var users = userRepository.findByTenantIdWithMetadata(tempTenantId);

            if (users.isEmpty()) {
                log.debug("No users found with temporary tenant ID: {}, removing from tracker",
                        tempTenantId);
                temporaryTenantTracker.removeTemporaryTenant(tempTenantId);
                return;
            }

            // Get correlation ID for retry
            String correlationId = temporaryTenantTracker.getCorrelationId(tempTenantId);

            for (var user : users) {
                log.warn("User {} still has temporary tenant ID {} after {}",
                        user.getId(), tempTenantId, staleDuration);

                // Options:
                // 1. Retry tenant creation
                // 2. Mark user for manual intervention
                // 3. Send alert to operations team

                // For now, mark user account
                user.getMetadata().put("tenant_creation_stale", "true");
                user.getMetadata().put("stale_since", String.valueOf(System.currentTimeMillis()));
                userRepository.save(user);

                // You might want to republish the tenant creation command here
                // or send an alert to operations
            }

        } catch (Exception e) {
            log.error("Error handling stale tenant: {}", tempTenantId, e);
        }
    }
}