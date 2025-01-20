package com.codingdrama.authservice.service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;

/**
 VerifyPassPhrasesMfaRequest class represents a request object for verifying mfa passphrases.
 */
@Getter
@Setter
@Schema(description = "Verify passphrases Request")
public class VerifyPassPhrasesMfaRequest {

    @NotNull
    @Schema(description = "User passPhrases")
    private Map<String, String> passPhrases;
}
