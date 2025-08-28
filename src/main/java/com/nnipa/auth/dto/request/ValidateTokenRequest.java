package com.nnipa.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Token validation request DTO.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Token validation request")
public class ValidateTokenRequest {

    @NotBlank(message = "Token is required")
    @Schema(description = "JWT token to validate", example = "eyJhbGciOiJIUzUxMiJ9...")
    private String token;

    @Schema(description = "Token type (access or refresh)", example = "access")
    private String tokenType = "access";
}