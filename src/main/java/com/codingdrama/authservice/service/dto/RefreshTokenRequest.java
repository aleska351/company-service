package com.codingdrama.authservice.service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * Represents a request to refresh an access token using a refresh token.
 */
@Data
public class RefreshTokenRequest {

    /**
     * The refresh token used to obtain a new access token.
     */
    @Schema(description = "The refresh token used to obtain a new access token")
    private String refreshToken;
}
