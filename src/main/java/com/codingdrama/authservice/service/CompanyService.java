package com.codingdrama.authservice.service;

import com.codingdrama.authservice.dto.CompanyDto;

import java.util.List;
import java.util.Optional;

public interface CompanyService {
    List<CompanyDto> getAllCompanies();
    Optional<CompanyDto> getCompanyById(Long id);
    CompanyDto createCompany(CompanyDto companyDto);
    CompanyDto updateCompany(Long id, CompanyDto companyDto);
    void deleteCompany(Long id);
}
