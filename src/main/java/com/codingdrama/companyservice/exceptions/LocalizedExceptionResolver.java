package com.codingdrama.companyservice.exceptions;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.springframework.context.MessageSource;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.FORBIDDEN;

@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
public class LocalizedExceptionResolver extends ResponseEntityExceptionHandler {
    private final MessageSource messageSource;

    public LocalizedExceptionResolver(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @ExceptionHandler(LocalizedResponseStatusException.class)
    public ResponseEntity<LocalizedResponse> handleException(LocalizedResponseStatusException e, HttpServletRequest request) {
        LocalizedResponse localizedResponse = new LocalizedResponse(e, messageSource.getMessage(e.getReason(), null, Locale.getDefault()), request.getRequestURI());
        return new ResponseEntity<>(localizedResponse, e.getStatusCode());
    }

    public ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException e, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        List<String> errors = new ArrayList<>();
        for (FieldError error : e.getBindingResult().getFieldErrors()) {
            errors.add("Field: " + error.getField() + " message:  " + error.getDefaultMessage());
        }
        for (ObjectError error : e.getBindingResult().getGlobalErrors()) {
            errors.add("Field: " + error.getObjectName() + " message: " + error.getDefaultMessage());
        }
        LocalizedResponseStatusException localizedResponseStatusException = new LocalizedResponseStatusException(HttpStatus.BAD_REQUEST, errors.toString());
        LocalizedResponse localizedResponse = new LocalizedResponse(localizedResponseStatusException, messageSource.getMessage(errors.toString(), null, Locale.getDefault()), ((ServletWebRequest) request).getRequest().getRequestURI());
        return new ResponseEntity<>(localizedResponse, HttpStatus.BAD_REQUEST);

    }

    @ExceptionHandler({ConstraintViolationException.class})
    public ResponseEntity<Object> handleConstraintViolation(
            ConstraintViolationException ex, WebRequest request) {
        List<String> errors = new ArrayList<>();
        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            errors.add(violation.getRootBeanClass().getName() + " " +
                               violation.getPropertyPath() + ": " + violation.getMessage());
        }

        LocalizedResponseStatusException localizedResponseStatusException = new LocalizedResponseStatusException(BAD_REQUEST, errors.toString());
        LocalizedResponse localizedResponse = new LocalizedResponse(localizedResponseStatusException, messageSource.getMessage(errors.toString(), null, Locale.getDefault()), ((ServletWebRequest) request).getRequest().getRequestURI());
        return new ResponseEntity<>(localizedResponse, BAD_REQUEST);
    }
}
