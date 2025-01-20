package com.codingdrama.authservice.service.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
public class LastLoginInfoDto{
    private String ip;
    private LocalDateTime date;
}
