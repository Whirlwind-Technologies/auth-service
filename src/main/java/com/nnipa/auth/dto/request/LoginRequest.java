package com.nnipa.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Login request DTO for username/password authentication.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Login request with username/email and password")
public class LoginRequest {

    @NotBlank(message = "Username or email is required")
    @Schema(description = "Username or email address", example = "john.doe@example.com")
    private String username;

    @NotBlank(message = "Password is required")
    @Schema(description = "User password", example = "SecurePassword123!")
    private String password;

    @Schema(description = "Tenant code for multi-tenant authentication", example = "TENANT001")
    private String tenantCode;

    @Schema(description = "Remember me flag for extended session", example = "true")
    private Boolean rememberMe = false;

    @Schema(description = "Device information for session tracking", example = "Chrome on Windows")
    private String deviceInfo;
}