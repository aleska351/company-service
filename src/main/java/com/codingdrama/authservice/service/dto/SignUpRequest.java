package com.codingdrama.authservice.service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import lombok.NoArgsConstructor;

/**

 Represents a request for user sign up with username and password.
 */
@Schema(description = "Sign up user request")
@Data
@NoArgsConstructor
public class SignUpRequest {


    @Schema(description = "User email")
    @NotBlank
    private String email;

    @Schema(description = "User password. Password should contains 8 characters or more in a combination of 3 or more of uppercase English letters, lowercase English letters, numbers, and special characters and no more than 2 consecutive letters, numbers, and special characters")
    @Pattern(regexp = "^(?!.*\\d{3})(?!.*[a-z]{3})(?!.*[A-Z]{3})(?=((?=.*[a-z])(?=.*\\d)(?=.*[!@#&()–\\[{}\\]:;',?/*~$^+=<>]))|((?=.*[A-Z])(?=.*\\d)(?=.*[!@#&()–\\[{}\\]:;',?/*~$^+=<>]))|((?=.*[a-z])(?=.*[A-Z])(?=.*\\d))|((?=.*[a-z])(?=.*[A-Z])(?=.*[!@#&()–\\[{}\\]:;',?/*~$^+=<>]))|((?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#&()–\\[{}\\]:;',?/*~$^+=<>])))(?!.*[!@#&()–\\[{}\\]:;',?/*~$^+=<>]{3}).{8,}$", message = "Password should contains 8 characters or more in a combination of 3 or more of uppercase English letters, lowercase English letters, numbers, and special characters and no more than 2 consecutive letters, numbers, and special characters")
    @NotBlank
    private String password;

    @Schema(description = "Receive marketing by email")
    private boolean isEmailMarketing = Boolean.FALSE;

    @Schema(description = "Receive marketing by sms")
    private boolean isPhoneMarketing = Boolean.FALSE;
}
