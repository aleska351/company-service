package com.codingdrama.authservice.security;

import com.codingdrama.authservice.service.dto.UserDto;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;


@Getter
public class AuthenticatedUserDetails implements UserDetails {
    private Long userId;
    private String email;
    private boolean authenticated;
    private boolean passwordExpired;
    private String secret;

    private String hash;
    private boolean emailVerified;
    private boolean mfaEnabled;
    private LocalDateTime loginDate;
    
    private Collection<? extends GrantedAuthority> authorities;

    public AuthenticatedUserDetails(UserDto user) {
        if (user == null) return;
        this.userId = user.getId();
        this.email = user.getEmail();

        this.authenticated = user.isAuthenticated();
        this.emailVerified = user.isEmailVerified();
        this.mfaEnabled = user.isMfaEnabled();

        this.secret = user.getSecret();
        this.hash = user.getHash();
                
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.passwordExpired;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
