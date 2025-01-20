package com.codingdrama.authservice.service;


import kr.co.bdacs.bdacs_user_service.model.auth.PassPhrases;

import java.util.List;
import java.util.Map;

/**
 An interface representing a service for managing secure tokens for user email authentication and password reset.
 */
public interface PassPhrasesService {

    /**
     Creates a new pass phrases for mfa for the given user ID.
     @param userId the ID of the user for whom to create the pass phrases
     @return the created list with  mfa pass phrases
     */
    List<String> createPassPhrases(Long userId);

    /**
     Saves the given pass phrases to the database.
     @param userId the ID of the user for whom to create the pass phrases
     @param passPhrases the recovery phrases for restore mfa
     */
    void savePassPhrases(Long userId, List<PassPhrases> passPhrases);

    /**
     Finds a pass phrases by the user ID associated with it.
     @param userId the user ID to search for
     @return the found pass phrases, or empty list if no pass phrases was found
     */
    List<PassPhrases> findByUserId(final Long userId);

    /**
     Removes the pass phrases from the database.
     @param userId the user ID to search for
     */
    void removePassPhrases( Long userId);

    /**
     Compares the passphrases provided in the request with the passphrase of the user with the given userId.
     Returns true if all the passphrases match, false otherwise.
     @param userId The userId of the user whose passphrase is being compared.
     @param requestPassPhrases A map containing the passphrases provided in the request with keys as "passphrase1", "passphrase2", "passphrase3" and values as the corresponding passphrase strings.
     @throw LocalizedResponseStatusException if mfa phrases invalid
     */
    void comparePassPhrases(Long userId, Map<String, String> requestPassPhrases);
}
