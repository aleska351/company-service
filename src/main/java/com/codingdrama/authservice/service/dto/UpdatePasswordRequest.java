package com.codingdrama.authservice.service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

/**
 UpdatePasswordRequest class represents a request object for updating a user's password.
 */
@Getter
@Setter
@Schema(description = "Reset Password Request")
public class UpdatePasswordRequest {
    @NotBlank
    @Schema(description = "New password")
    @Pattern(regexp = "^(?!.*\\d{3})(?!.*[a-z]{3})(?!.*[A-Z]{3})(?=((?=.*[a-z])(?=.*\\d)(?=.*[!@#&()–\\[{}\\]:;',?/*~$^+=<>]))|((?=.*[A-Z])(?=.*\\d)(?=.*[!@#&()–\\[{}\\]:;',?/*~$^+=<>]))|((?=.*[a-z])(?=.*[A-Z])(?=.*\\d))|((?=.*[a-z])(?=.*[A-Z])(?=.*[!@#&()–\\[{}\\]:;',?/*~$^+=<>]))|((?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#&()–\\[{}\\]:;',?/*~$^+=<>])))(?!.*[!@#&()–\\[{}\\]:;',?/*~$^+=<>]{3}).{8,}$", message = "Password should contains 8 characters or more in a combination of 3 or more of uppercase English letters, lowercase English letters, numbers, and special characters and no more than 2 consecutive letters, numbers, and special characters")
    private String password;
}
