package com.codingdrama.authservice.exceptions;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

import java.util.Date;
/**
 * Represents a localized response returned by the API when an error occurs.
 */
@Getter
@Setter
public class LocalizedResponse {
    /**
     * The timestamp when the error occurred.
     */
    private final Date timestamp;

    /**
     * The HTTP status code of the response.
     */
    private final int status;

    /**
     * The HTTP status of the response.
     */
    private final HttpStatus error;

    /**
     * The localized error message.
     */
    private final String message;

    /**
     * The default error message if no localized message is available.
     */
    private final String defaultMessage;

    /**
     * The unique identifier of the error.
     */
    private final String errorId;

    /**
     * The request path that resulted in the error.
     */
    private final String path;

    /**
     * Constructs a new localized response from a localized exception.
     *
     * @param e              the localized exception that triggered the response
     * @param defaultMessage the default error message to use if no localized message is available
     * @param path           the request path that resulted in the error
     */
    public LocalizedResponse(LocalizedResponseStatusException e, String defaultMessage,  String path) {
        this.timestamp = e.getTimestamp();
        this.error = HttpStatus.resolve(e.getStatusCode().value());
        this.status = e.getStatusCode().value();
        this.message = e.getReason();
        this.defaultMessage = defaultMessage;
        this.errorId = e.getErrorId();
        this.path = path;
    }
}
