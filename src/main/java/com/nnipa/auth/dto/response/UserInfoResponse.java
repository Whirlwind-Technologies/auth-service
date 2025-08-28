package com.nnipa.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.nnipa.auth.enums.AuthProvider;
import com.nnipa.auth.enums.UserStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;


/**
 * User information response DTO.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "User information")
public class UserInfoResponse {

    @Schema(description = "User ID")
    private UUID id;

    @Schema(description = "Tenant ID")
    private UUID tenantId;

    @Schema(description = "External user ID from user-management-service")
    private UUID externalUserId;

    @Schema(description = "Username")
    private String username;

    @Schema(description = "Email address")
    private String email;

    @Schema(description = "Email verification status")
    private Boolean emailVerified;

    @Schema(description = "Phone number")
    private String phoneNumber;

    @Schema(description = "Phone verification status")
    private Boolean phoneVerified;

    @Schema(description = "User account status")
    private UserStatus status;

    @Schema(description = "Primary authentication provider")
    private AuthProvider primaryAuthProvider;

    @Schema(description = "MFA enabled status")
    private Boolean mfaEnabled;

    @Schema(description = "Last login timestamp")
    private LocalDateTime lastLoginAt;

    @Schema(description = "Linked OAuth2 providers")
    private Set<String> linkedProviders;

    @Schema(description = "Account creation timestamp")
    private LocalDateTime createdAt;
}
