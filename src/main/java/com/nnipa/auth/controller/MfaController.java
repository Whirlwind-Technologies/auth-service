package com.nnipa.auth.controller;

import com.nnipa.auth.dto.request.MfaSetupRequest;
import com.nnipa.auth.dto.request.MfaVerificationRequest;
import com.nnipa.auth.dto.response.ApiResponse;
import com.nnipa.auth.dto.response.MfaSetupResponse;
import com.nnipa.auth.enums.MfaType;
import com.nnipa.auth.service.MfaService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * REST controller for Multi-Factor Authentication management.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/mfa")
@RequiredArgsConstructor
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "MFA", description = "Multi-Factor Authentication management APIs")
public class MfaController {

    private final MfaService mfaService;

    @PostMapping("/setup/totp")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Setup TOTP MFA", description = "Initialize TOTP (Google Authenticator) for the user")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "TOTP setup initiated",
                    content = @Content(schema = @Schema(implementation = MfaSetupResponse.class))
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "409",
                    description = "TOTP already configured"
            )
    })
    public ResponseEntity<ApiResponse<MfaSetupResponse>> setupTotp(
            @AuthenticationPrincipal UUID userId,
            @RequestParam(required = false) String deviceName) {

        log.info("TOTP setup requested for user: {}", userId);

        Map<String, String> setup = mfaService.setupTotp(userId, deviceName);

        MfaSetupResponse response = MfaSetupResponse.builder()
                .type(MfaType.TOTP)
                .secret(setup.get("secret"))
                .qrCode(setup.get("qrCode"))
                .deviceId(UUID.fromString(setup.get("deviceId")))
                .message("Scan the QR code with your authenticator app and verify with a code")
                .build();

        return ResponseEntity.ok(ApiResponse.success(response, "TOTP setup initiated"));
    }

    @PostMapping("/setup/sms")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Setup SMS MFA", description = "Initialize SMS-based MFA for the user")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "SMS MFA setup initiated"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid phone number"
            )
    })
    public ResponseEntity<ApiResponse<MfaSetupResponse>> setupSms(
            @AuthenticationPrincipal UUID userId,
            @Valid @RequestBody MfaSetupRequest request) {

        log.info("SMS MFA setup requested for user: {}", userId);

        Map<String, String> setup = mfaService.setupSms(userId, request.getPhoneNumber());

        MfaSetupResponse response = MfaSetupResponse.builder()
                .type(MfaType.SMS)
                .deviceId(UUID.fromString(setup.get("deviceId")))
                .maskedPhoneNumber(setup.get("maskedPhoneNumber"))
                .message(setup.get("message"))
                .build();

        return ResponseEntity.ok(ApiResponse.success(response, "SMS verification code sent"));
    }

    @PostMapping("/verify/{deviceId}")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Verify and enable MFA device", description = "Verify MFA setup with code")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "MFA device verified and enabled"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid verification code"
            )
    })
    public ResponseEntity<ApiResponse<Boolean>> verifyDevice(
            @AuthenticationPrincipal UUID userId,
            @PathVariable UUID deviceId,
            @Valid @RequestBody MfaVerificationRequest request) {

        log.info("MFA device verification for device: {}", deviceId);

        boolean verified = mfaService.verifyAndEnableTotp(deviceId, request.getCode());

        if (verified) {
            return ResponseEntity.ok(ApiResponse.success(true, "MFA device verified and enabled"));
        } else {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Invalid verification code", "INVALID_CODE"));
        }
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify MFA code", description = "Verify MFA code during authentication")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "MFA code verified"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid MFA code"
            )
    })
    public ResponseEntity<ApiResponse<Boolean>> verifyCode(
            @Valid @RequestBody MfaVerificationRequest request) {

        log.debug("MFA code verification request");

        // Extract user ID from MFA token
        UUID userId = extractUserIdFromMfaToken(request.getMfaToken());

        boolean valid = mfaService.verifyMfaCode(userId, request.getCode(), request.getType());

        if (valid) {
            return ResponseEntity.ok(ApiResponse.success(true, "MFA verification successful"));
        } else {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Invalid MFA code", "INVALID_MFA_CODE"));
        }
    }

    @GetMapping("/devices")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Get user's MFA devices", description = "List all MFA devices for the authenticated user")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "MFA devices retrieved"
            )
    })
    public ResponseEntity<ApiResponse<List<MfaService.MfaDeviceInfo>>> getUserDevices(
            @AuthenticationPrincipal UUID userId) {

        log.debug("Fetching MFA devices for user: {}", userId);

        List<MfaService.MfaDeviceInfo> devices = mfaService.getUserMfaDevices(userId);

        return ResponseEntity.ok(ApiResponse.success(devices, "MFA devices retrieved"));
    }

    @DeleteMapping("/devices/{deviceId}")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Disable MFA device", description = "Disable a specific MFA device")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "MFA device disabled"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "Device not found"
            )
    })
    public ResponseEntity<ApiResponse<Void>> disableDevice(
            @AuthenticationPrincipal UUID userId,
            @PathVariable UUID deviceId) {

        log.info("Disabling MFA device {} for user: {}", deviceId, userId);

        mfaService.disableMfaDevice(userId, deviceId);

        return ResponseEntity.ok(ApiResponse.success(null, "MFA device disabled"));
    }

    @PostMapping("/backup-codes")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Generate backup codes", description = "Generate new set of backup codes")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Backup codes generated"
            )
    })
    public ResponseEntity<ApiResponse<List<String>>> generateBackupCodes(
            @AuthenticationPrincipal UUID userId) {

        log.info("Generating backup codes for user: {}", userId);

        List<String> codes = mfaService.generateBackupCodes(userId);

        return ResponseEntity.ok(ApiResponse.success(codes,
                "Backup codes generated. Store them securely - they won't be shown again."));
    }

    @PostMapping("/send-code")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Send MFA code", description = "Send MFA code via SMS or email")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "MFA code sent"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "MFA not configured"
            )
    })
    public ResponseEntity<ApiResponse<Void>> sendMfaCode(
            @AuthenticationPrincipal UUID userId,
            @RequestParam MfaType type) {

        log.info("Sending {} MFA code for user: {}", type, userId);

        if (type == MfaType.SMS) {
            mfaService.sendSmsCode(userId);
            return ResponseEntity.ok(ApiResponse.success(null, "SMS code sent"));
        } else {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Unsupported MFA type for code sending", "UNSUPPORTED_TYPE"));
        }
    }

    // Helper method to extract user ID from MFA token
    private UUID extractUserIdFromMfaToken(String mfaToken) {
        // This would use JwtTokenProvider to extract user ID
        // Implementation depends on your token structure
        return UUID.randomUUID(); // Placeholder
    }
}