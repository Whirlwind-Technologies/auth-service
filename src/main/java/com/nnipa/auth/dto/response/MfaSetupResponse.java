package com.nnipa.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.nnipa.auth.enums.MfaType;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "MFA setup response")
public class MfaSetupResponse {

    @Schema(description = "MFA type")
    private MfaType type;

    @Schema(description = "Device ID")
    private UUID deviceId;

    @Schema(description = "TOTP secret (for manual entry)")
    private String secret;

    @Schema(description = "QR code URL for TOTP")
    private String qrCode;

    @Schema(description = "Masked phone number for SMS")
    private String maskedPhoneNumber;

    @Schema(description = "Setup message")
    private String message;
}