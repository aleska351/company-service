package com.codingdrama.authservice.security.jwt;

import com.codingdrama.hrsystem.security.AuthenticatedUserDetails;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthentication extends AbstractAuthenticationToken {
    private final String credentials;
    private final String principal;

    public JwtAuthentication(AuthenticatedUserDetails userDetails, String jwtToken, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.setAuthenticated(true);
        this.credentials = jwtToken;
        this.principal = userDetails.getUsername();
        this.setDetails(userDetails);
    }


    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public AuthenticatedUserDetails getAuthenticatedUserDetails(){
        return (AuthenticatedUserDetails) super.getDetails();
    }
}
