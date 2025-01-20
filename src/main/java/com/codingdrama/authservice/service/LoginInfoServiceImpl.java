package com.codingdrama.authservice.service;

import kr.co.bdacs.bdacs_user_service.model.auth.LastLoginInfo;
import kr.co.bdacs.bdacs_user_service.repository.auth.LoginInfoRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class LoginInfoServiceImpl implements LoginInfoService{

    private final LoginInfoRepository loginInfoRepository;

    public LoginInfoServiceImpl(LoginInfoRepository loginInfoRepository) {
        this.loginInfoRepository = loginInfoRepository;
    }
    @Override
    public LastLoginInfo findLogin(Long userId) {
        return loginInfoRepository.findByUserId(userId).orElse(null);
    }


    @Override
    public LastLoginInfo saveLogin(Long userId, String ip) {
        LastLoginInfo loginInfo = loginInfoRepository.findByUserId(userId).orElse(new LastLoginInfo());
        loginInfo.setIp(ip);
        loginInfo.setDate(LocalDateTime.now());
        loginInfo.setUserId(userId);
        loginInfoRepository.save(loginInfo);
        return loginInfo;
    }


    @Override
    public void removeLogin(Long userId) {
        loginInfoRepository.removeByUserId(userId);
    }
}
