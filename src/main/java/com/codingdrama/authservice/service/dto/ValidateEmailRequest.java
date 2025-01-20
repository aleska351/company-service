package com.codingdrama.authservice.service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Request object for validating an email address via MailChecker api.
 */
@Data
@AllArgsConstructor
public class ValidateEmailRequest {

    /**
     * The email address to validate.
     */
    private String email;
}

