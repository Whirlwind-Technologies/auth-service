package com.nnipa.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "MFA setup request")
public class MfaSetupRequest {

    @Pattern(regexp = "^\\+[1-9]\\d{1,14}$", message = "Invalid phone number format (E.164)")
    @Schema(description = "Phone number for SMS MFA", example = "+1234567890")
    private String phoneNumber;

    @Schema(description = "Device name for TOTP", example = "My Phone")
    private String deviceName;
}