package com.codingdrama.authservice.service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 Represents a request for user login with username and password.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequestDto {
    @NotBlank
    private String email;
    @NotBlank
    private String password;
}
