package com.codingdrama.authservice.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.annotation.CreatedDate;

import java.time.LocalDateTime;
import java.util.Objects;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name="last_login_info")
public class LastLoginInfo extends BaseEntity {
    @Column
    private String ip;
    @CreationTimestamp
    @CreatedDate
    private LocalDateTime date;

    @Column(name = "user_id")
    private Long userId;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        LastLoginInfo that = (LastLoginInfo) o;
        return ip.equals(that.ip) && date.equals(that.date);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), ip, date);
    }
}
