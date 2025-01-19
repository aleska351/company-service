package com.codingdrama.companyservice.repository;

import com.codingdrama.companyservice.dto.CompanyDto;
import com.codingdrama.companyservice.entity.Company;
import com.codingdrama.companyservice.exceptions.LocalizedResponseStatusException;
import com.codingdrama.companyservice.util.Util;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.BeanUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class CompanyService {
    private final CompanyRepository companyRepository;
    private final ModelMapper modelMapper;
    
    public List<CompanyDto> getAllCompanies() {
        return companyRepository.findAll().stream().map(company -> modelMapper.map(company, CompanyDto.class)).collect(Collectors.toList());
    }

    public Optional<CompanyDto> getCompanyById(Long id) {
        return companyRepository.findById(id).map(company -> modelMapper.map(company, CompanyDto.class));
    }

    public CompanyDto createCompany(CompanyDto companyDto) {
         Company company = modelMapper.map(companyDto, Company.class);
        return modelMapper.map(companyRepository.save(company), CompanyDto.class);
    }
    
    
    public CompanyDto updateCompany(Long id, CompanyDto companyDTO) {
        Company existingCompany = companyRepository.findById(id)
                .orElseThrow(() -> new LocalizedResponseStatusException(HttpStatus.NOT_FOUND, "company.not.found"));
        
        BeanUtils.copyProperties(companyDTO, existingCompany, Util.getNullPropertyNames(companyDTO));

        return modelMapper.map(companyRepository.save(existingCompany), CompanyDto.class);
    }

    public void deleteCompany(Long id) {
        companyRepository.deleteById(id);
    }
}
