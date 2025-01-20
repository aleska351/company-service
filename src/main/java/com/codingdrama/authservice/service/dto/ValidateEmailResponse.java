package com.codingdrama.authservice.service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 A DTO class representing the response received after validating an email address via MailChecker api.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ValidateEmailResponse {

    /**
     * The status of the email address validation.
     */
    private String status;
}

