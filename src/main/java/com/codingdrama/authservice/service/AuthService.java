package com.codingdrama.authservice.service;

import dev.samstevens.totp.exceptions.QrGenerationException;
import jakarta.servlet.http.HttpServletRequest;
import kr.co.bdacs.bdacs_user_service.security.AuthenticatedUserDetails;
import kr.co.bdacs.bdacs_user_service.service.dto.LoginRequestDto;
import kr.co.bdacs.bdacs_user_service.service.dto.LoginResponseDto;
import kr.co.bdacs.bdacs_user_service.service.dto.MfaTokenData;
import kr.co.bdacs.bdacs_user_service.service.dto.SignUpRequest;
import kr.co.bdacs.bdacs_user_service.service.dto.VerifyPassPhrasesMfaRequest;

/**
 An interface representing a service for managing user credentials. Login registration logout etc.
 */
public interface AuthService {

    /**
     * Registers a new user and returns a LoginResponseDto object with the user's information and an authentication token.
     * @param request the sign-up request containing user information
     * @param ip the IP address of the user making the request
     * @return a LoginResponseDto object containing user information and an authentication token
     */
    LoginResponseDto register(SignUpRequest request, String ip);

    /**
     * Logs in a user and returns a LoginResponseDto object with the user's information and an authentication token.
     * @param loginRequest the login request containing user credentials
     * @param httpServletRequest the servlet request object
     * @return a LoginResponseDto object containing user information and an authentication token
     */
    LoginResponseDto login(LoginRequestDto loginRequest, HttpServletRequest httpServletRequest);

    /**
     * Initiates the process of setting up MFA for a user and returns the MfaTokenData object with QR code data.
     * @param email the email address of the user requesting MFA setup
     * @return an MfaTokenData object with QR code data
     * @throws QrGenerationException if an error occurs while generating the QR code
     */
    MfaTokenData mfaSetup(final String email) throws QrGenerationException;

    /**
     * Verifies the user's MFA token and returns a LoginResponseDto object with the user's information and an authentication token.
     * @param email the email address of the user verifying their MFA token
     * @param token the MFA token to verify
     * @param ip the IP address of the user making the request
     * @return a LoginResponseDto object containing user information and an authentication token
     */
    LoginResponseDto verifyUserMfa(String email, String token, String ip);

    /**
     * Verifies a user's email address using a confirmation token.
     * @param email the email address of the user to verify
     * @param token the confirmation token
     */
    void verifyUserEmail(final String email, final String token);

    /**
     * Sends a password reset email to a user.
     * @param email the email address of the user requesting a password reset
     * @param ip the IP address of the user making the request
     * @return a LoginResponseDto object containing user information and an authentication token
     */
    LoginResponseDto requestPasswordReset(String email, String ip);

    /**
     * Sends a mfa reset email to a user.
     * @param email the email address of the user requesting a mfa reset
     * @param ip the IP address of the user making the request
     * @return a LoginResponseDto object containing user information and an authentication token
     */
    LoginResponseDto requestMfaReset(String email, String ip);

    /**
     * Verify mfa passphrases for user.
     * @param verifyPassPhrasesMfaRequest user passphrases for recovering mfa
     * @return a MfaTokenData object with QR code data
     */
    MfaTokenData verifyMfaReset(String email, VerifyPassPhrasesMfaRequest verifyPassPhrasesMfaRequest) throws QrGenerationException;

    /**
     * Updates a user's password.
     * @param email the email address of the user whose password is being updated
     * @param password the new password
     */
    void updatePassword(String email, String password);

    /**
     * Put off user's password updating to 90 days.
     * @param email the email address of the user whose password is being updated
     */
    void updatePasswordLatter(String email);

    /**
     * Logs out a user.
     * @param email the email address of the user to log out
     */
    void logout(String email);

    /**
     * Resend email code  to a user.
     * @param user current user
     */
    void resendEmailConfirmationEmail(AuthenticatedUserDetails user);


    /**
     * Resend mfa passphrases  to a user.
     * @param user current user
     */
    void resendPassPhrasesEmail(AuthenticatedUserDetails user);

    /**
     * Refreshes an access token using a refresh token.
     *
     * @param accessToken  the current access token
     * @param refreshToken the refresh token used to obtain a new access token
     * @param ip the IP address of the user making the request
     * @return a LoginResponseDto object containing the new access token and its expiration time
     * @throws kr.co.bdacs.bdacs_user_service.exceptions.LocalizedResponseStatusException if the current access token or refresh token is invalid
     */
    LoginResponseDto refreshAccessToken(String accessToken, String refreshToken, String ip);
}

