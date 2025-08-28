package com.nnipa.auth.dto.request;

import com.nnipa.auth.enums.MfaType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "MFA verification request")
public class MfaVerificationRequest {

    @NotBlank(message = "MFA code is required")
    @Pattern(regexp = "^[0-9]{6,8}$", message = "MFA code must be 6-8 digits")
    @Schema(description = "MFA verification code", example = "123456")
    private String code;

    @NotNull(message = "MFA type is required")
    @Schema(description = "Type of MFA", example = "TOTP")
    private MfaType type;

    @Schema(description = "MFA token from initial authentication")
    private String mfaToken;
}