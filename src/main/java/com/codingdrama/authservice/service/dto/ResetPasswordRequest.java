package com.codingdrama.authservice.service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

/**
 ResetPasswordRequest class represents a request object for resetting a user's password.
 */
@Getter
@Setter
@Schema(description = "Reset Password Request")
public class ResetPasswordRequest {
    @NotBlank
    @Schema(description = "Email for password reset")
    private String email;
}
