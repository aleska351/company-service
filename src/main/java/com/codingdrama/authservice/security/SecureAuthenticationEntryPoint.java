package com.codingdrama.authservice.security;

import com.codingdrama.hrsystem.exceptions.LocalizedResponse;
import com.codingdrama.hrsystem.exceptions.LocalizedResponseStatusException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Locale;
import java.util.Objects;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Component
public class SecureAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final MessageSource messageSource;

    private ObjectMapper objectMapper;

    public SecureAuthenticationEntryPoint(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        response.addHeader("Content-Type", "application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        LocalizedResponseStatusException localizedResponseStatusException = new LocalizedResponseStatusException(UNAUTHORIZED, "unauthorized.request");
        LocalizedResponse localizedResponse = new LocalizedResponse(localizedResponseStatusException, messageSource.getMessage(Objects.requireNonNull(localizedResponseStatusException.getReason()), null, Locale.getDefault()), request.getRequestURI());
        objectMapper.writeValue(response.getOutputStream(), localizedResponse);
        response.flushBuffer();
    }
    
    @Autowired
    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }
}
