package com.codingdrama.companyservice.repository;

import com.codingdrama.companyservice.entity.Company;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CompanyRepository extends JpaRepository<Company, Long> {
}
