package com.nnipa.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Authentication response DTO.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Authentication response with tokens and user info")
public class AuthResponse {

    @Schema(description = "JWT access token")
    private String accessToken;

    @Schema(description = "JWT refresh token")
    private String refreshToken;

    @Schema(description = "Token type", example = "Bearer")
    private String tokenType = "Bearer";

    @Schema(description = "Access token expiration in seconds", example = "900")
    private Long expiresIn;

    @Schema(description = "Refresh token expiration in seconds", example = "604800")
    private Long refreshExpiresIn;

    @Schema(description = "Authenticated user information")
    private UserInfoResponse user;

    @Schema(description = "MFA required flag", example = "false")
    private Boolean mfaRequired = false;

    @Schema(description = "MFA token for verification (when MFA is required)")
    private String mfaToken;

    @Schema(description = "Authentication timestamp")
    private LocalDateTime authenticatedAt;
}