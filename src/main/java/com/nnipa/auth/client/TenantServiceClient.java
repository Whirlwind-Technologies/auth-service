package com.nnipa.auth.client;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import java.util.UUID;

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

    @Data
    private static class TenantResponse {
        private UUID id;
        private String tenantCode;
        private String name;
    }
}