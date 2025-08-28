package com.nnipa.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;
import java.util.UUID;

/**
 * Token validation response DTO.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Token validation response")
public class TokenValidationResponse {

    @Schema(description = "Token validity status")
    private Boolean valid;

    @Schema(description = "User ID from token")
    private UUID userId;

    @Schema(description = "Tenant ID from token")
    private UUID tenantId;

    @Schema(description = "Username from token")
    private String username;

    @Schema(description = "Token expiration timestamp (Unix epoch)")
    private Long expiresAt;

    @Schema(description = "Token issued at timestamp (Unix epoch)")
    private Long issuedAt;

    @Schema(description = "Token JWT ID")
    private String jti;

    @Schema(description = "Additional token claims")
    private Map<String, Object> claims;

    @Schema(description = "Validation error message (if invalid)")
    private String errorMessage;
}