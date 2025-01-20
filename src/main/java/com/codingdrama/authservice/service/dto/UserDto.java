package com.codingdrama.authservice.service.dto;

import jakarta.persistence.Column;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

/**
 * Data Transfer Object class representing a user.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {
    private Long id;
    private String email;
    private String password;
    private boolean authenticated;

    private boolean passwordChangeEmailVerified;
    private boolean passwordChangeMfaVerified;

    private String secret;
    private String hash;
    private boolean emailVerified;
    private boolean mfaVerified;
    private boolean mfaEnabled;
    private boolean kybVerified;
    private Date passwordExpiredDate;

    
    

    private LastLoginInfoDto lastLoginInfo;
}
