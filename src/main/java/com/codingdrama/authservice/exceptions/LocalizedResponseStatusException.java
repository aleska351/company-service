package com.codingdrama.authservice.exceptions;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.Date;

/**
 * Represents a localized response status exception to avoid creating error for each case.
 */
@Getter
@Setter
public class LocalizedResponseStatusException extends ResponseStatusException {
    private final Logger logger = LoggerFactory.getLogger(LocalizedResponseStatusException.class);

    /**
     * The timestamp when the error occurred.
     */
    private final Date timestamp;
    /**
     * The unique identifier of the error.
     */
    private final String errorId;

    public LocalizedResponseStatusException(HttpStatus status, String reason) {
        super(status, reason);
        this.timestamp = new Date();
        this.errorId = RandomStringUtils.random(20, true, true);
        logger.error("Error: " + reason + " , error id: " + this.errorId + " , timestamp: " + this.timestamp);
    }
}
