package com.codingdrama.authservice.service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.List;

/**
 Data Transfer Object class representing user profile.
 */
@Schema(description = "User profile")
@Data
public class UserProfileDto {

    @Schema(description = "Corporate Korean name")
    private String corporateKoreanName;

    @Schema(description = "CEO or representative directors on Korean")
    private List<RepresentativeDirectorDto> representativeDirectors;

    @Schema(description = "Corporate English name")
    private String corporateEnglishName;

    @Schema(description = "Corporate registration number")
    private String corporateRegistrationNumber;

    @Schema(description = "Company registration number")
    private String companyRegistrationNumber;

    @Schema(description = "Corporate phone number")
    private String corporatePhoneNumber;

    @Schema(description = "Corporate website")
    private String corporateWebsite;

    @Schema(description = "Manager Korean name")
    private String managerKoreanName;

    @Schema(description = "Manager English first name")
    private String managerEnglishFirstName;

    @Schema(description = "Manager English last name")
    private String managerEnglishLastName;

    @Schema(description = "Manager Korean title")
    private String managerKoreanTitle;

    @Schema(description = "Manager phone number")
    private String managerPhoneNumber;

    @Schema(description = "Manager email ")
    private String managerEmail;
}
