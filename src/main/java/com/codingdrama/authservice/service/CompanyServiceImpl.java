package com.codingdrama.authservice.service;

import com.codingdrama.authservice.dto.CompanyDto;
import com.codingdrama.authservice.entity.Company;
import com.codingdrama.authservice.exceptions.LocalizedResponseStatusException;
import com.codingdrama.authservice.repository.CompanyRepository;
import com.codingdrama.authservice.util.Util;
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
public class CompanyServiceImpl implements CompanyService {
    private final CompanyRepository companyRepository;
    private final ModelMapper modelMapper;
    
    @Override
    public List<CompanyDto> getAllCompanies() {
        return companyRepository.findAll().stream().map(company -> modelMapper.map(company, CompanyDto.class)).collect(Collectors.toList());
    }
    
    @Override
    public Optional<CompanyDto> getCompanyById(Long id) {
        return companyRepository.findById(id).map(company -> modelMapper.map(company, CompanyDto.class));
    }

    @Override
    public CompanyDto createCompany(CompanyDto companyDto) {
         Company company = modelMapper.map(companyDto, Company.class);
        return modelMapper.map(companyRepository.save(company), CompanyDto.class);
    }
    
    @Override
    public CompanyDto updateCompany(Long id, CompanyDto companyDTO) {
        Company existingCompany = companyRepository.findById(id)
                .orElseThrow(() -> new LocalizedResponseStatusException(HttpStatus.NOT_FOUND, "company.not.found"));
        
        BeanUtils.copyProperties(companyDTO, existingCompany, Util.getNullPropertyNames(companyDTO));

        return modelMapper.map(companyRepository.save(existingCompany), CompanyDto.class);
    }

    @Override
    public void deleteCompany(Long id) {
        companyRepository.deleteById(id);
    }
}
