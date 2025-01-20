package com.codingdrama.authservice.service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**

 Data class representing the MFA token information.
 */
@Schema(description = "MFA token Including base64 QR code and mfa code")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class MfaTokenData {
    /**
      The base64-encoded URL of the QR code image for the user's MFA configuration.
     */
    @Schema(description = "Base64-encoded URL of the QR")
    private String qrCode;

    @Schema(description = "The MFA code for the user to enter during the MFA setup process if user have not ability scan qr code")
    /**
     The MFA code for the user to enter during the MFA setup process if user have not ability scan qr code.
     */
    private String mfaCode;
}
