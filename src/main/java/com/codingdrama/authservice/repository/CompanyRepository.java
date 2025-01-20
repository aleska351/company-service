package com.codingdrama.authservice.repository;

import com.codingdrama.authservice.entity.Company;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CompanyRepository extends JpaRepository<Company, Long> {
}
