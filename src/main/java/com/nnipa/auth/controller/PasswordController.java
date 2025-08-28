package com.nnipa.auth.controller;

import com.nnipa.auth.dto.request.ChangePasswordRequest;
import com.nnipa.auth.dto.request.PasswordResetRequest;
import com.nnipa.auth.dto.request.ResetPasswordRequest;
import com.nnipa.auth.dto.response.ApiResponse;
import com.nnipa.auth.entity.User;
import com.nnipa.auth.service.PasswordService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

/**
 * REST controller for password management.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/password")
@RequiredArgsConstructor
@Tag(name = "Password", description = "Password management APIs")
public class PasswordController {

    private final PasswordService passwordService;

    @PostMapping("/change")
    @PreAuthorize("isAuthenticated()")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Change password", description = "Change password for authenticated user")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password changed successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid password or validation failed"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Current password incorrect"
            )
    })
    public ResponseEntity<ApiResponse<Void>> changePassword(
            @AuthenticationPrincipal UUID userId,
            @Valid @RequestBody ChangePasswordRequest request) {

        log.info("Password change requested for user: {}", userId);

        passwordService.changePassword(userId, request.getCurrentPassword(), request.getNewPassword());

        return ResponseEntity.ok(ApiResponse.success(null, "Password changed successfully"));
    }

    @PostMapping("/reset-request")
    @Operation(summary = "Request password reset", description = "Initiate password reset process")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password reset email sent"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "Email not found"
            )
    })
    public ResponseEntity<ApiResponse<Void>> requestPasswordReset(
            @Valid @RequestBody PasswordResetRequest request,
            HttpServletRequest httpRequest) {

        log.info("Password reset requested for email: {}", request.getEmail());

        String ipAddress = getClientIpAddress(httpRequest);
        passwordService.initiatePasswordReset(request.getEmail(), ipAddress);

        // Always return success to prevent email enumeration
        return ResponseEntity.ok(ApiResponse.success(null,
                "If the email exists, a password reset link has been sent"));
    }

    @PostMapping("/reset")
    @Operation(summary = "Reset password", description = "Reset password using token")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password reset successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid or expired token"
            )
    })
    public ResponseEntity<ApiResponse<Void>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {

        log.info("Password reset with token");

        User user = passwordService.resetPassword(request.getToken(), request.getNewPassword());

        return ResponseEntity.ok(ApiResponse.success(null, "Password reset successfully"));
    }

    @PostMapping("/validate")
    @Operation(summary = "Validate password", description = "Check if password meets policy requirements")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password validation result"
            )
    })
    public ResponseEntity<ApiResponse<PasswordService.PasswordValidationResult>> validatePassword(
            @RequestBody Map<String, String> request) {

        String password = request.get("password");
        String username = request.get("username");
        String email = request.get("email");

        PasswordService.PasswordValidationResult result =
                passwordService.validatePassword(password, username, email);

        return ResponseEntity.ok(ApiResponse.success(result));
    }

    @GetMapping("/policy")
    @Operation(summary = "Get password policy", description = "Get current password policy requirements")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password policy retrieved"
            )
    })
    public ResponseEntity<ApiResponse<Map<String, Object>>> getPasswordPolicy() {

        Map<String, Object> policy = Map.of(
                "minLength", 12,
                "requireUppercase", true,
                "requireLowercase", true,
                "requireDigit", true,
                "requireSpecial", true,
                "maxAgeDays", 90,
                "historyCount", 5
        );

        return ResponseEntity.ok(ApiResponse.success(policy, "Password policy retrieved"));
    }

    @PostMapping("/generate")
    @Operation(summary = "Generate secure password", description = "Generate a secure random password")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password generated"
            )
    })
    public ResponseEntity<ApiResponse<String>> generatePassword() {

        String password = passwordService.generateSecurePassword();

        return ResponseEntity.ok(ApiResponse.success(password, "Secure password generated"));
    }

    @GetMapping("/expired")
    @PreAuthorize("isAuthenticated()")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Check password expiration", description = "Check if user's password is expired")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password expiration status"
            )
    })
    public ResponseEntity<ApiResponse<Boolean>> checkPasswordExpired(
            @AuthenticationPrincipal UUID userId) {

        boolean expired = passwordService.isPasswordExpired(userId);

        return ResponseEntity.ok(ApiResponse.success(expired,
                expired ? "Password is expired" : "Password is valid"));
    }

    // Helper method to get client IP address
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}