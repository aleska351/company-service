package com.codingdrama.authservice.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table( name = "users")
public class User extends BaseEntity {

    @Column(unique = true, nullable = false)
    private String email;
    @Column
    private String password;
    @Column
    private boolean authenticated = Boolean.FALSE;

    @Column
    private Date passwordExpiredDate;
    
    @Column
    private String secret;

    @Column
    private String hash;

    @Column
    private boolean emailVerified;
    @Column
    private boolean mfaVerified;

    @Column
    private boolean passwordChangeEmailVerified = Boolean.TRUE;
    @Column
    private boolean passwordChangeMfaVerified = Boolean.TRUE;
}
