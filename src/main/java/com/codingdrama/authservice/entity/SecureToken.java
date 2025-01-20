package com.codingdrama.authservice.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import kr.co.bdacs.bdacs_user_service.model.BaseEntity;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.Objects;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "secure_tokens")
public class SecureToken extends BaseEntity {

    @Column
    private String token;

    private LocalDateTime expireAt;

    @ToString.Exclude
    @Column(name = "user_id")
    private Long userId;

    @Transient
    private boolean isExpired;
    public boolean isExpired() {
        return getExpireAt().isBefore(LocalDateTime.now());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        SecureToken that = (SecureToken) o;
        return isExpired == that.isExpired && token.equals(that.token) && expireAt.equals(that.expireAt) && userId.equals(that.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), token, expireAt, userId, isExpired);
    }
}
