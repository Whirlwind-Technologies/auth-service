package com.nnipa.auth.client;

import com.nnipa.proto.tenant.*;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.client.inject.GrpcClient;
import org.springframework.stereotype.Component;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * gRPC Client for communicating with tenant-service.
 * Replaces the WebClient-based TenantServiceClient.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TenantGrpcClient {

    @GrpcClient("tenant-service")
    private TenantServiceGrpc.TenantServiceBlockingStub tenantServiceBlockingStub;

    @GrpcClient("tenant-service")
    private TenantServiceGrpc.TenantServiceFutureStub tenantServiceFutureStub;

    /**
     * Check if tenant exists using gRPC.
     *
     * @param tenantId the tenant ID to check
     * @return true if tenant exists, false otherwise
     */
    public boolean tenantExists(UUID tenantId) {
        try {
            log.debug("Checking tenant existence via gRPC: {}", tenantId);

            TenantExistsRequest request = TenantExistsRequest.newBuilder()
                    .setTenantId(tenantId.toString())
                    .build();

            TenantExistsResponse response = tenantServiceBlockingStub.tenantExists(request);

            log.debug("Tenant exists check result: {} with status: {}",
                    response.getExists(), response.getStatus());

            return response.getExists();

        } catch (StatusRuntimeException e) {
            if (e.getStatus().getCode() == Status.Code.NOT_FOUND) {
                log.debug("Tenant not found: {}", tenantId);
                return false;
            }
            log.error("gRPC error checking tenant existence: {}", tenantId, e);
            return false;
        } catch (Exception e) {
            log.error("Unexpected error checking tenant existence: {}", tenantId, e);
            return false;
        }
    }

    /**
     * Get tenant ID by code using gRPC.
     *
     * @param tenantCode the tenant code to look up
     * @return the tenant ID if found, null otherwise
     */
    public UUID getTenantIdByCode(String tenantCode) {
        try {
            log.debug("Getting tenant by code via gRPC: {}", tenantCode);

            GetTenantByCodeRequest request = GetTenantByCodeRequest.newBuilder()
                    .setTenantCode(tenantCode)
                    .build();

            GetTenantResponse response = tenantServiceBlockingStub.getTenantByCode(request);

            UUID tenantId = UUID.fromString(response.getTenantId());
            log.debug("Found tenant with ID: {} for code: {}", tenantId, tenantCode);

            return tenantId;

        } catch (StatusRuntimeException e) {
            if (e.getStatus().getCode() == Status.Code.NOT_FOUND) {
                log.debug("Tenant not found with code: {}", tenantCode);
                return null;
            }
            log.error("gRPC error fetching tenant by code: {}", tenantCode, e);
            return null;
        } catch (Exception e) {
            log.error("Unexpected error fetching tenant by code: {}", tenantCode, e);
            return null;
        }
    }

    /**
     * Create a new tenant synchronously using gRPC.
     * This is the primary method that replaces the WebClient createTenant method.
     *
     * @param organizationName the name of the organization
     * @param organizationEmail the email of the organization
     * @param correlationId the correlation ID for tracking
     * @return CompletableFuture with the created tenant's UUID
     */
    public CompletableFuture<UUID> createTenant(String organizationName,
                                                String organizationEmail,
                                                String correlationId, UUID userId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                log.info("Creating tenant via gRPC for organization: {} with correlationId: {}",
                        organizationName, correlationId);

                // Generate tenant code from organization name
                String tenantCode = generateTenantCode(organizationName);

                CreateTenantRequest request = CreateTenantRequest.newBuilder()
                        .setName(organizationName)
                        .setEmail(organizationEmail)
                        .setTenantCode(tenantCode)
                        .setOrganizationType("ENTERPRISE")
                        .setSubscriptionPlan("FREEMIUM")        // Default plan for self-signup
                        .setCreatedBy(userId.toString())
                        .setCorrelationId(correlationId)
                        .build();

                CreateTenantResponse response = tenantServiceBlockingStub.createTenant(request);

                UUID tenantId = UUID.fromString(response.getTenantId());
                log.info("Successfully created tenant via gRPC with ID: {} for organization: {}",
                        tenantId, organizationName);

                return tenantId;

            } catch (StatusRuntimeException e) {
                log.error("gRPC error creating tenant for organization: {} with correlationId: {}",
                        organizationName, correlationId, e);
                throw new RuntimeException("Failed to create tenant: " + e.getStatus().getDescription(), e);
            } catch (Exception e) {
                log.error("Unexpected error creating tenant for organization: {} with correlationId: {}",
                        organizationName, correlationId, e);
                throw new RuntimeException("Failed to create tenant", e);
            }
        });
    }

    /**
     * Get tenant details by ID using gRPC.
     *
     * @param tenantId the tenant ID
     * @return TenantInfo object with tenant details, or null if not found
     */
    public TenantInfo getTenantById(UUID tenantId) {
        try {
            log.debug("Getting tenant by ID via gRPC: {}", tenantId);

            GetTenantRequest request = GetTenantRequest.newBuilder()
                    .setTenantId(tenantId.toString())
                    .build();

            GetTenantResponse response = tenantServiceBlockingStub.getTenant(request);

            return TenantInfo.builder()
                    .id(UUID.fromString(response.getTenantId()))
                    .tenantCode(response.getTenantCode())
                    .name(response.getName())
                    .email(response.getEmail())
                    .status(response.getStatus())
                    .subscriptionPlan(response.getSubscriptionPlan())
                    .build();

        } catch (StatusRuntimeException e) {
            if (e.getStatus().getCode() == Status.Code.NOT_FOUND) {
                log.debug("Tenant not found: {}", tenantId);
                return null;
            }
            log.error("gRPC error getting tenant: {}", tenantId, e);
            return null;
        } catch (Exception e) {
            log.error("Unexpected error getting tenant: {}", tenantId, e);
            return null;
        }
    }

    /**
     * Get tenant status using gRPC.
     *
     * @param tenantId the tenant ID
     * @return TenantStatus object with status information, or null if not found
     */
    public TenantStatus getTenantStatus(UUID tenantId) {
        try {
            log.debug("Getting tenant status via gRPC: {}", tenantId);

            GetTenantStatusRequest request = GetTenantStatusRequest.newBuilder()
                    .setTenantId(tenantId.toString())
                    .build();

            GetTenantStatusResponse response = tenantServiceBlockingStub.getTenantStatus(request);

            return TenantStatus.builder()
                    .tenantId(UUID.fromString(response.getTenantId()))
                    .status(response.getStatus())
                    .isActive(response.getIsActive())
                    .userCount(response.getUserCount())
                    .subscriptionStatus(response.getSubscriptionStatus())
                    .build();

        } catch (StatusRuntimeException e) {
            if (e.getStatus().getCode() == Status.Code.NOT_FOUND) {
                log.debug("Tenant not found for status check: {}", tenantId);
                return null;
            }
            log.error("gRPC error getting tenant status: {}", tenantId, e);
            return null;
        } catch (Exception e) {
            log.error("Unexpected error getting tenant status: {}", tenantId, e);
            return null;
        }
    }

    /**
     * Activate a tenant using gRPC.
     *
     * @param tenantId the tenant ID to activate
     * @param activatedBy the user who is activating the tenant
     * @return true if successful, false otherwise
     */
    public boolean activateTenant(UUID tenantId, String activatedBy) {
        try {
            log.info("Activating tenant via gRPC: {} by user: {}", tenantId, activatedBy);

            ActivateTenantRequest request = ActivateTenantRequest.newBuilder()
                    .setTenantId(tenantId.toString())
                    .setActivatedBy(activatedBy)
                    .build();

            tenantServiceBlockingStub.activateTenant(request);

            log.info("Successfully activated tenant: {}", tenantId);
            return true;

        } catch (StatusRuntimeException e) {
            log.error("gRPC error activating tenant: {}", tenantId, e);
            return false;
        } catch (Exception e) {
            log.error("Unexpected error activating tenant: {}", tenantId, e);
            return false;
        }
    }

    /**
     * Suspend a tenant using gRPC.
     *
     * @param tenantId the tenant ID to suspend
     * @param reason the reason for suspension
     * @param suspendedBy the user who is suspending the tenant
     * @return true if successful, false otherwise
     */
    public boolean suspendTenant(UUID tenantId, String reason, String suspendedBy) {
        try {
            log.info("Suspending tenant via gRPC: {} for reason: {} by user: {}",
                    tenantId, reason, suspendedBy);

            SuspendTenantRequest request = SuspendTenantRequest.newBuilder()
                    .setTenantId(tenantId.toString())
                    .setReason(reason)
                    .setSuspendedBy(suspendedBy)
                    .build();

            tenantServiceBlockingStub.suspendTenant(request);

            log.info("Successfully suspended tenant: {}", tenantId);
            return true;

        } catch (StatusRuntimeException e) {
            log.error("gRPC error suspending tenant: {}", tenantId, e);
            return false;
        } catch (Exception e) {
            log.error("Unexpected error suspending tenant: {}", tenantId, e);
            return false;
        }
    }

    // Helper method to generate tenant code
    private String generateTenantCode(String organizationName) {
        String cleanName = organizationName.toUpperCase()
                .replaceAll("[^A-Z0-9]", "");
        String prefix = cleanName.length() >= 3 ?
                cleanName.substring(0, 3) : cleanName;
        String suffix = UUID.randomUUID().toString().substring(0, 6).toUpperCase();
        return prefix + suffix;
    }

    // Inner classes for response DTOs

    @lombok.Data
    @lombok.Builder
    public static class TenantInfo {
        private UUID id;
        private String tenantCode;
        private String name;
        private String email;
        private String status;
        private String subscriptionPlan;
    }

    @lombok.Data
    @lombok.Builder
    public static class TenantStatus {
        private UUID tenantId;
        private String status;
        private boolean isActive;
        private int userCount;
        private String subscriptionStatus;
    }
}