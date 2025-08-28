package com.nnipa.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * User registration request DTO.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "New user registration request")
public class RegisterRequest {

    @NotBlank(message = "Tenant code is required")
    @Schema(description = "Tenant code for organization", example = "TENANT001")
    private String tenantCode;

    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9._-]+$", message = "Username can only contain letters, numbers, dots, underscores and hyphens")
    @Schema(description = "Unique username", example = "john.doe")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Schema(description = "Email address", example = "john.doe@example.com")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 12, message = "Password must be at least 12 characters")
    @Schema(description = "Password (min 12 chars, must include uppercase, lowercase, number, special char)")
    private String password;

    @NotBlank(message = "Password confirmation is required")
    @Schema(description = "Password confirmation (must match password)")
    private String confirmPassword;

    @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$", message = "Invalid phone number format")
    @Schema(description = "Phone number in E.164 format", example = "+1234567890")
    private String phoneNumber;

    @Schema(description = "Enable MFA on registration", example = "false")
    private Boolean enableMfa = false;
}