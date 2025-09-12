package com.nnipa.auth.dto.request;

import com.nnipa.auth.enums.RegistrationType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.*;

/**
 * User registration request DTO.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "User registration request")
public class RegisterRequest {

    @NotNull(message = "Registration type is required")
    @Schema(description = "Registration type: SELF_SIGNUP or ADMIN_CREATED", example = "SELF_SIGNUP")
    private RegistrationType registrationType;

    // For ADMIN_CREATED type - existing tenant
    @Schema(description = "Tenant ID for admin-created users (required for ADMIN_CREATED type)")
    private String tenantId;

    // For SELF_SIGNUP type - new tenant info
    @Schema(description = "Organization name (required for SELF_SIGNUP type)")
    private String organizationName;

    @Schema(description = "Organization type (for SELF_SIGNUP type)")
    private String organizationType;

    @Schema(description = "Organization email (for SELF_SIGNUP type)")
    private String organizationEmail;

    // Common user fields
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

    @Schema(description = "First name")
    private String firstName;

    @Schema(description = "Last name")
    private String lastName;

    @Schema(description = "Enable MFA on registration", example = "false")
    private Boolean enableMfa = false;

    // For ADMIN_CREATED type - role assignment
    @Schema(description = "Initial role for admin-created users")
    private String initialRole;
}