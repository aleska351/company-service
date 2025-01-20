package com.codingdrama.authservice.service;


import kr.co.bdacs.bdacs_user_service.model.auth.LastLoginInfo;

/**
 The LoginInfoService interface defines methods for managing login informatio related to user accounts.
 */
public interface LoginInfoService {

    /**
     Finds a last login info by the user ID associated with it.
     @param userId the user ID to search for
     @return the last login info, or null if no login was found
     */
    LastLoginInfo findLogin(Long userId);

    /**

     Saves the last login information for a user with the given user ID.
     @param userId the ID of the user for whom to save the last login information
     @param ip the IP address of the user who logged in
     @return the last login information that was saved
     @throws kr.co.bdacs.bdacs_user_service.exceptions.LocalizedResponseStatusException if an error occurs while attempting to save the information
     */
    LastLoginInfo saveLogin(Long userId, String ip);


    /**

     Remove the last login information for a user with the given user ID.
     @param userId the ID of the user for whom to removed the last login information
     */
    void removeLogin(Long userId);
}
