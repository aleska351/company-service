package com.codingdrama.authservice.service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;

import java.util.List;

/**
 Represents a request for updating account.
 */
@Schema(description = "Account profile update request")
@Data
@NoArgsConstructor
public class UpdateAccountRequest {

    @Schema(description = "Corporate Korean name")
    @NotBlank
    @Length(max = 60)
    private String corporateKoreanName;

    @NotEmpty
    @Schema(description = "CEO or  representative directors on Korean")
    private List<String> representativeDirectors;

    @Schema(description = "Corporate English name")
    @NotBlank
    @Length(max = 60)
    private String corporateEnglishName;

    @Schema(description = "Corporate registration number. Should be in format \"XXXXXX-XXXXXXX\"")
    @Pattern(regexp = "^\\d{6}-\\d{7}$", message = "Corporate registration number should be in format \"XXXXXX-XXXXXXX\"")
    @NotBlank
    private String corporateRegistrationNumber;

    @Schema(description = "Company registration number. Should be in format \"XXX-XX-XXXXX\"")
    @Pattern(regexp = "^\\d{3}-\\d{2}-\\d{5}$", message = "Company registration number should be in format \"XXX-XX-XXXXX\"")
    @NotBlank
    private String companyRegistrationNumber;


    @Schema(description = "Corporate phone number.")
    @Pattern(regexp = "^\\d{9,20}$", message = "Phone number number should contain more than 8 digits")
    private String corporatePhoneNumber;

    @Schema(description = "Corporate website")
    private String corporateWebsite;

    @Schema(description = "Manager Korean name")
    @Pattern(regexp = "^[가-힣]*$", message = "Only Korean allowed")
    @NotBlank
    @Length(max = 30)
    private String managerKoreanName;

    @Schema(description = "Manager English first name")
    @NotBlank
    @Length(max = 30)
    private String managerEnglishFirstName;

    @Schema(description = "Manager English last name")
    @NotBlank
    @Length(max = 30)
    private String managerEnglishLastName;

    @Schema(description = "Manager Korean title")
    @NotBlank
    @Length(max = 60)
    private String managerKoreanTitle;

    @Schema(description = "Manager phone number.")
    @Pattern(regexp = "^\\d{9,20}$", message = "Phone number number should contain more than 8 digits")
    @NotBlank
    private String managerPhoneNumber;

    @Schema(description = "Manager email ")
    @NotBlank
    private String managerEmail;
}
