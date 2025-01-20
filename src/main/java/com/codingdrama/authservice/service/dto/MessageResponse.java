package com.codingdrama.authservice.service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

/**
 MessageResponse Object class representing response message  to return success or error messages in response to API requests.
 */
@Schema(description = "Response message  to return success or error messages in response to API requests.")
@Data
@AllArgsConstructor
public class MessageResponse {

    @Schema(description = "Response message.")
    private String message;
}
