package com.codingdrama.authservice.service.dto;

import jakarta.persistence.Column;
import lombok.Data;


@Data
public class RepresentativeDirectorDto {

    @Column
    private String name;
}
