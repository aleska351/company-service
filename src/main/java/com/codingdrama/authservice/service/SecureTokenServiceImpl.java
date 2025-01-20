package com.codingdrama.authservice.service;

import kr.co.bdacs.bdacs_user_service.model.auth.SecureToken;
import kr.co.bdacs.bdacs_user_service.repository.auth.SecureTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Random;

@Service
public class SecureTokenServiceImpl implements SecureTokenService {

    @Value("${bdacs.email.secure.token.expired}")
    private int tokenExpiredInSeconds;

    private final SecureTokenRepository secureTokenRepository;

    public SecureTokenServiceImpl(SecureTokenRepository secureTokenRepository) {
        this.secureTokenRepository = secureTokenRepository;
    }

    @Override
    public SecureToken createSecureToken(Long userId){
        String randomToken = String.format("%06d", new Random().nextInt(999999));
        SecureToken secureToken = new SecureToken();
        secureToken.setToken(randomToken);
        secureToken.setUserId(userId);
        secureToken.setExpireAt(LocalDateTime.now().plusSeconds(getTokenExpiredInSeconds()));
        this.saveSecureToken(secureToken);
        return secureToken;
    }

    @Override
    public void saveSecureToken(SecureToken token) {
        SecureToken existedToken = findByUserId(token.getUserId());
        if(Objects.nonNull(existedToken)){
            removeToken(existedToken);
        }
        secureTokenRepository.save(token);
    }

    @Override
    public SecureToken findByToken(String token) {
        return secureTokenRepository.findByToken(token);
    }

    @Override
    public SecureToken findByUserId(Long userId) {
        return secureTokenRepository.findByUserId(userId);
    }

    @Override
    public void removeToken(SecureToken token) {
        secureTokenRepository.delete(token);
    }

    public int getTokenExpiredInSeconds() {
        return tokenExpiredInSeconds;
    }
}
