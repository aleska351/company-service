package com.codingdrama.companyservice.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity
@Table(name = "companies")
public class Company {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(nullable = false)
    private String address;

    private String email;

    private String phone;

    @Column(unique = true)
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

