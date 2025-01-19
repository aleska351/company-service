package com.codingdrama.companyservice.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Data
public class CompanyDto {
    private Long id;
    private String name;
    private String address;
    private String email;
    private String phone;
    private String taxId;
    private String registrationNumber;
    private String industry;
    private String streetAddress;
    private String city;
    private String stateOrProvince;
    private String zipOrPostalCode;
    private String country;
    private String contactPerson;
    private String contactEmail;
    private String contactPhone;
    private Boolean isActive;
}
