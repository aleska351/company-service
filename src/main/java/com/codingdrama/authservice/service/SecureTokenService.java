package com.codingdrama.authservice.service;


import kr.co.bdacs.bdacs_user_service.model.auth.SecureToken;

/**
 An interface representing a service for managing secure tokens for user email authentication and password reset.
 */
public interface SecureTokenService {

    /**
     Creates a new secure number token for the given user ID.
     @param userId the ID of the user for whom to create the token
     @return the created secure number token
     */
    SecureToken createSecureToken(final Long userId);

    /**
     Saves the given secure token to the database.
     @param token the secure token to save
     */
    void saveSecureToken(final SecureToken token);

    /**
     Finds a secure token by its token string.
     @param token the token string to search for
     @return the found secure token, or null if no token was found
     */
    SecureToken findByToken(final String token);

    /**
     Finds a secure token by the user ID associated with it.
     @param userId the user ID to search for
     @return the found secure token, or null if no token was found
     */
    SecureToken findByUserId(final Long userId);

    /**
     Removes the given secure token from the database.
     @param token the secure token to remove
     */
    void removeToken(final SecureToken token);
}
