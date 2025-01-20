package com.codingdrama.authservice.security.jwt;

import com.codingdrama.hrsystem.exceptions.LocalizedResponse;
import com.codingdrama.hrsystem.exceptions.LocalizedResponseStatusException;
import com.codingdrama.hrsystem.util.UserUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Locale;
import java.util.Objects;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;
    private final ObjectMapper objectMapper;
    private MessageSource messageSource;

    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider, ObjectMapper objectMapper) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = UserUtil.getAuthorizationToken(request);
        try {
            if (Objects.nonNull(token) && jwtTokenProvider.validateToken(token)) {
                Authentication authentication = jwtTokenProvider.getAuthentication(token, UserUtil.getClientIP(request));
                if (Objects.nonNull(authentication)) {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else {
                    throw new BadCredentialsException("JWT Token have invalid state");
                }
            }

            filterChain.doFilter(request, response);
        } catch (LocalizedResponseStatusException e) {
            LocalizedResponse localizedResponse = new LocalizedResponse(e, messageSource.getMessage(Objects.requireNonNull(e.getReason()), null, Locale.getDefault()), request.getRequestURI());
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write(objectMapper.writeValueAsString(localizedResponse));
            response.flushBuffer();
        }
    }

    @Autowired
    public void setMessageSource(MessageSource messageSource) {
        this.messageSource = messageSource;
    }
}
