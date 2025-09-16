package com.nnipa.auth.client;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Client for communicating with tenant-service.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TenantServiceClient {

    private final WebClient.Builder webClientBuilder;

    @Value("${services.tenant-service.url:http://tenant-service:4001}")
    private String tenantServiceUrl;

    /**
     * Check if tenant exists.
     */
    public boolean tenantExists(UUID tenantId) {
        try {
            WebClient webClient = webClientBuilder.baseUrl(tenantServiceUrl).build();
            return webClient
                    .get()
                    .uri("/api/v1/tenants/{id}", tenantId)
                    .retrieve()
                    .onStatus(HttpStatusCode::is4xxClientError, response -> Mono.empty())
                    .bodyToMono(Object.class)
                    .blockOptional()
                    .isPresent();
        } catch (Exception e) {
            log.error("Error checking tenant existence: {}", tenantId, e);
            return false;
        }
    }

    /**
     * Get tenant ID by code.
     */
    public UUID getTenantIdByCode(String tenantCode) {
        try {
            WebClient webClient = webClientBuilder.baseUrl(tenantServiceUrl).build();
            TenantResponse response = webClient
                    .get()
                    .uri("/api/v1/tenants/code/{code}", tenantCode)
                    .retrieve()
                    .onStatus(HttpStatusCode::is4xxClientError,
                            clientResponse -> Mono.error(new RuntimeException("Tenant not found")))
                    .bodyToMono(TenantResponse.class)
                    .block();
            return response != null ? response.getId() : null;
        } catch (Exception e) {
            log.error("Error fetching tenant by code: {}", tenantCode, e);
            return null;
        }
    }

    /**
     * Create a new tenant.
     */
    public CompletableFuture<UUID> createTenant(String organizationName, String organizationEmail, String correlationId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                log.info("Creating tenant for organization: {} with correlationId: {}", organizationName, correlationId);

                WebClient webClient = webClientBuilder.baseUrl(tenantServiceUrl).build();

                CreateTenantRequest request = new CreateTenantRequest();
                request.setName(organizationName);
                request.setEmail(organizationEmail);
                request.setCorrelationId(correlationId);

                TenantResponse response = webClient
                        .post()
                        .uri("/api/v1/tenants")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(request)
                        .retrieve()
                        .onStatus(HttpStatusCode::is4xxClientError,
                                clientResponse -> {
                                    log.error("Client error creating tenant: {}", clientResponse.statusCode());
                                    return Mono.error(new RuntimeException("Failed to create tenant: " + clientResponse.statusCode()));
                                })
                        .onStatus(HttpStatusCode::is5xxServerError,
                                serverResponse -> {
                                    log.error("Server error creating tenant: {}", serverResponse.statusCode());
                                    return Mono.error(new RuntimeException("Server error creating tenant: " + serverResponse.statusCode()));
                                })
                        .bodyToMono(TenantResponse.class)
                        .block();

                if (response != null && response.getId() != null) {
                    log.info("Successfully created tenant with ID: {} for organization: {}", response.getId(), organizationName);
                    return response.getId();
                } else {
                    log.error("Received null response or null ID when creating tenant for organization: {}", organizationName);
                    throw new RuntimeException("Failed to create tenant: received null response");
                }

            } catch (Exception e) {
                log.error("Error creating tenant for organization: {} with correlationId: {}", organizationName, correlationId, e);
                throw new RuntimeException("Failed to create tenant", e);
            }
        });
    }

    @Data
    private static class TenantResponse {
        private UUID id;
        private String tenantCode;
        private String name;
        private String email;
    }

    @Data
    private static class CreateTenantRequest {
        private String name;
        private String email;
        private String correlationId;
    }
}