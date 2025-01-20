package com.codingdrama.authservice.security;

import com.codingdrama.hrsystem.exceptions.LocalizedResponseStatusException;
import com.codingdrama.hrsystem.service.UserService;
import com.codingdrama.hrsystem.service.dto.UserDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class JWTUserDetailsService implements UserDetailsService {
    private final UserService userService;

    @Autowired
    public JWTUserDetailsService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try{
            UserDto user = userService.findByEmail(username);
            AuthenticatedUserDetails authenticatedUserDetails = new AuthenticatedUserDetails(user);
            log.info("User with username: {} successfully loaded", username);
            return authenticatedUserDetails;
        }catch (LocalizedResponseStatusException e){
            throw new UsernameNotFoundException("User with email: " + username + " not found");
        }
    }
}
