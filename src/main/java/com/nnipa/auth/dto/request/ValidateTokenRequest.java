package com.nnipa.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Token validation request DTO.
 * Now optional since token comes from Authorization header.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Token validation request (optional body for additional parameters)")
public class ValidateTokenRequest {

    @Schema(description = "Token type (access or refresh)", example = "access", defaultValue = "access")
    private String tokenType = "access";

    @Schema(description = "Additional validation options", example = "true")
    private Boolean includeUserDetails = true;
}