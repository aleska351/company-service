package com.codingdrama.authservice.service;

import kr.co.bdacs.bdacs_user_service.exceptions.LocalizedResponseStatusException;
import kr.co.bdacs.bdacs_user_service.model.auth.PassPhrases;
import kr.co.bdacs.bdacs_user_service.repository.auth.PassPhrasesRepository;
import kr.co.bdacs.bdacs_user_service.service.mfa.MfaTokenManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
public class PassPhrasesServiceImpl implements PassPhrasesService {

    @Value("${bdacs.mfa.passphrases.expired}")
    private int mfaPassPhrasesExpired;
    private final PassPhrasesRepository passPhrasesRepository;
    private final MfaTokenManager mfaTokenManager;

    public PassPhrasesServiceImpl(PassPhrasesRepository passPhrasesRepository, MfaTokenManager mfaTokenManager) {
        this.passPhrasesRepository = passPhrasesRepository;
        this.mfaTokenManager = mfaTokenManager;
    }

    @Override
    public List<String> createPassPhrases(Long userId) {
        List<String> recoveryPhrases = mfaTokenManager.generateRecoveryPhrases();
        LocalDateTime expiredAt = LocalDateTime.now().plusSeconds(getMfaPassPhrasesExpired());

        List<PassPhrases> passPhrases = IntStream.range(0, recoveryPhrases.size())
                                                .mapToObj(i -> new PassPhrases(i + 1, recoveryPhrases.get(i), expiredAt, userId))
                                                .collect(Collectors.toList());

        this.savePassPhrases(userId, passPhrases);
        return passPhrases.stream().map(PassPhrases::getRecoveryPhrase).toList();
    }

    @Override
    public void savePassPhrases(Long userId, List<PassPhrases> passPhrases) {
        List<PassPhrases> existedPassPhrases = findByUserId(userId);
        if (Objects.nonNull(existedPassPhrases) && !existedPassPhrases.isEmpty()) {
            removePassPhrases(userId);
        }
        passPhrasesRepository.saveAll(passPhrases);
    }


    @Override
    public List<PassPhrases> findByUserId(Long userId) {
        return passPhrasesRepository.findByUserId(userId);
    }

    @Transactional
    @Override
    public void removePassPhrases(Long userId) {
        passPhrasesRepository.deleteAllByUserId(userId);
    }

    @Transactional
    public void comparePassPhrases(Long userId, Map<String, String> requestPassPhrases) {
        if (requestPassPhrases.size() < 3)
            throw new LocalizedResponseStatusException(HttpStatus.BAD_REQUEST, "mfa.passphrases.invalid");
        List<PassPhrases> passPhrases = findByUserId(userId);
        List<String> recoveryPhrases = passPhrases.stream().map(PassPhrases::getRecoveryPhrase).toList();
        passPhrases.stream().forEach(passPhrase -> {
            if (passPhrase.isExpired()) {
                throw new LocalizedResponseStatusException(HttpStatus.BAD_REQUEST, "mfa.passphrases.invalid");
            }
        });

        Map<String, String> userPassPhrasesMap = passPhrases.stream()
                                                         .collect(Collectors.toMap(
                                                                 passPhrase -> String.valueOf(passPhrase.getPassId()),
                                                                 PassPhrases::getRecoveryPhrase,
                                                                 (a, b) -> b,
                                                                 HashMap::new));

        boolean isEqual = true;

        for (Map.Entry<String, String> entry : requestPassPhrases.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            if (!userPassPhrasesMap.containsKey(key) || !userPassPhrasesMap.get(key).equals(value)) {
                isEqual = false;
                break;
            }
        }
        if (!isEqual) {
            throw new LocalizedResponseStatusException(HttpStatus.BAD_REQUEST, "mfa.passphrases.invalid");
        }
    }

    public int getMfaPassPhrasesExpired() {
        return mfaPassPhrasesExpired;
    }
}
