package com.codingdrama.authservice.service;

import dev.samstevens.totp.exceptions.QrGenerationException;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import kr.co.bdacs.bdacs_user_service.exceptions.LocalizedResponseStatusException;
import kr.co.bdacs.bdacs_user_service.model.Permission;
import kr.co.bdacs.bdacs_user_service.model.auth.LastLoginInfo;
import kr.co.bdacs.bdacs_user_service.model.auth.SecureToken;
import kr.co.bdacs.bdacs_user_service.model.auth.User;
import kr.co.bdacs.bdacs_user_service.model.auth.UserPassword;
import kr.co.bdacs.bdacs_user_service.model.userprofile.UserMarketing;
import kr.co.bdacs.bdacs_user_service.repository.auth.UserPasswordRepository;
import kr.co.bdacs.bdacs_user_service.repository.auth.UserRepository;
import kr.co.bdacs.bdacs_user_service.repository.userprofile.UserMarketingRepository;
import kr.co.bdacs.bdacs_user_service.security.AuthenticatedUserDetails;
import kr.co.bdacs.bdacs_user_service.security.bruteforce.CaptchaService;
import kr.co.bdacs.bdacs_user_service.security.jwt.JwtTokenProvider;
import kr.co.bdacs.bdacs_user_service.service.dto.LastLoginInfoDto;
import kr.co.bdacs.bdacs_user_service.service.dto.LoginRequestDto;
import kr.co.bdacs.bdacs_user_service.service.dto.LoginResponseDto;
import kr.co.bdacs.bdacs_user_service.service.dto.MfaTokenData;
import kr.co.bdacs.bdacs_user_service.service.dto.SignUpRequest;
import kr.co.bdacs.bdacs_user_service.service.dto.UserDto;
import kr.co.bdacs.bdacs_user_service.service.dto.VerifyPassPhrasesMfaRequest;
import kr.co.bdacs.bdacs_user_service.service.email.context.AccountRecoveryEmailContext;
import kr.co.bdacs.bdacs_user_service.service.email.context.AccountVerificationEmailContext;
import kr.co.bdacs.bdacs_user_service.service.email.context.FailedLoginEmailContext;
import kr.co.bdacs.bdacs_user_service.service.email.context.PasswordResetEmailVerificationContext;
import kr.co.bdacs.bdacs_user_service.service.email.context.SuccessLoginEmailContext;
import kr.co.bdacs.bdacs_user_service.service.email.service.EmailService;
import kr.co.bdacs.bdacs_user_service.service.mailchecker.MailCheckerServiceImpl;
import kr.co.bdacs.bdacs_user_service.service.mfa.MfaTokenManager;
import kr.co.bdacs.bdacs_user_service.utils.UserUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@Service
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;

    private final UserPasswordRepository userPasswordRepository;
    private final UserMarketingRepository userMarketingRepository;
    private final LoginInfoService loginInfoService;
    private final PassPhrasesService passPhrasesService;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final MfaTokenManager mfaTokenManager;
    private final CaptchaService captchaService;
    private final EmailService emailService;
    private final MailCheckerServiceImpl emailCheckerService;

    private final SecureTokenService secureTokenService;
    private PasswordEncoder passwordEncoder;

    private ModelMapper modelMapper;

    private final Map<String, Integer> attemptsCache = new ConcurrentHashMap<>();
    private final int maxAttempts = 5;

    @Value("${bdacs.password.expired}")
    private int passwordExpirationTime;



    public AuthServiceImpl(UserRepository userRepository, UserPasswordRepository userPasswordRepository, UserMarketingRepository userMarketingRepository, LoginInfoService loginInfoService, PassPhrasesService passPhrasesService, JwtTokenProvider jwtTokenProvider, AuthenticationManager authenticationManager, MfaTokenManager mfaTokenManager, CaptchaService captchaService, EmailService emailService, MailCheckerServiceImpl emailCheckerService, SecureTokenService secureTokenService) {
        this.userRepository = userRepository;
        this.userPasswordRepository = userPasswordRepository;
        this.userMarketingRepository = userMarketingRepository;
        this.loginInfoService = loginInfoService;
        this.passPhrasesService = passPhrasesService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.authenticationManager = authenticationManager;
        this.mfaTokenManager = mfaTokenManager;
        this.captchaService = captchaService;
        this.emailService = emailService;
        this.emailCheckerService = emailCheckerService;
        this.secureTokenService = secureTokenService;
    }

    @Override
    @Transactional
    public LoginResponseDto register(SignUpRequest request, String ip) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new LocalizedResponseStatusException(HttpStatus.BAD_REQUEST, "user.already.exist");
        }
        emailCheckerService.checkEmail(request.getEmail());

        String hash = UUID.randomUUID().toString();
        User user = modelMapper.map(request, User.class);
        encodePassword(request, user);
        user.setSecret(mfaTokenManager.generateSecretKey());
        Date now = new Date();
        user.setPasswordExpiredDate(new Date(now.getTime() + passwordExpirationTime));
        user.setHash(hash);

        User savedUser = userRepository.save(user);

        UserMarketing userMarketing = new UserMarketing();
        userMarketing.setUserId(savedUser.getId());
        userMarketing.setEmailMarketing(request.isEmailMarketing());
        userMarketing.setPhoneMarketing(request.isPhoneMarketing());
        userMarketingRepository.save(userMarketing);

        LastLoginInfo lastLoginInfo = loginInfoService.saveLogin(savedUser.getId(), ip);

        log.info("User: {} successfully registered", user);
        UserDto userDto = modelMapper.map(savedUser, UserDto.class);
        userDto.setLastLoginInfo(modelMapper.map(lastLoginInfo, LastLoginInfoDto.class));

        sendRegistrationConfirmationEmail(user.getId(), user.getEmail());

        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        String token = jwtTokenProvider.createToken(request.getEmail(), user.isAuthenticated(), hash, ip, authenticate.getAuthorities());

        return new LoginResponseDto(userDto, token, null);

    }

    @Override
    public LoginResponseDto login(LoginRequestDto loginRequest, HttpServletRequest httpServletRequest) {
        String username = loginRequest.getEmail();
        String ip = UserUtil.getClientIP(httpServletRequest);
        User user = userRepository.findByEmail(username).orElseThrow(() -> new LocalizedResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid.credentials"));
        try {
            user.setAuthenticated(false);
            String hash = UUID.randomUUID().toString();
            user.setHash(hash);
            user.setPasswordChangeEmailVerified(true);
            user.setPasswordChangeMfaVerified(true);
            User updatedUser = userRepository.save(user);
            if (attemptsCache.getOrDefault(username, 0) == maxAttempts) {
                log.error("Attempt to invalid login for email {} from ip {} at time {}", username, ip, LocalDateTime.now());
                sendFailedLoginEmail(user, ip);
            }

            if (isMaxAttemptsReached(username)) {
                String captchaResponse = UserUtil.getRecaptcha(httpServletRequest);
                captchaService.processResponse(captchaResponse, ip);
            }

            Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, loginRequest.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authenticate);
            clearCacheAttempt(username);
            String token = jwtTokenProvider.createToken(username, false, hash, ip, authenticate.getAuthorities());
            UserDto userDto = modelMapper.map(updatedUser, UserDto.class);
            if (!user.isEmailVerified()) resendEmailConfirmationEmail(new AuthenticatedUserDetails(userDto));
            log.info("Success login from email {} from ip {} at time {}", username, ip, LocalDateTime.now());
            LastLoginInfo login = loginInfoService.findLogin(user.getId());
            if(Objects.nonNull(login)){
                userDto.setLastLoginInfo(modelMapper.map(login, LastLoginInfoDto.class));
            }
            return new LoginResponseDto(userDto, token, null);
        } catch (AuthenticationException e) {
            cacheAttempt(username);
            log.error("Attempt to invalid login for email {} from ip {} at time {}", username, ip, LocalDateTime.now());
            throw new LocalizedResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid.credentials");
        }
    }

    @Override
    public MfaTokenData mfaSetup(String email) throws QrGenerationException {
        User user = getOrThrowNotFound(email);
        if (user.isMfaVerified()) {
            throw new LocalizedResponseStatusException(HttpStatus.BAD_REQUEST, "mfa.is.already.confirmed");
        }
        return new MfaTokenData(mfaTokenManager.getQRCode(user.getSecret(), email), user.getSecret());
    }

    @Transactional
    @Override
    public LoginResponseDto verifyUserMfa(String email, String token, String ip) {
        User user = getOrThrowNotFound(email);
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        if (!mfaTokenManager.verifyTotp(token, user.getSecret())) {
            throw new LocalizedResponseStatusException(HttpStatus.BAD_REQUEST, "invalid.mfa.token");
        }
        if (user.isMfaVerified() && user.isPasswordChangeMfaVerified()) sendSuccessLoginEmail(user, ip);
        if (!user.isMfaVerified()) {
            user.setMfaVerified(true);
        } else if (!user.isPasswordChangeMfaVerified()) {
            user.setPasswordChangeMfaVerified(true);
            if (user.isPasswordChangeEmailVerified()) {
                authorities.add(new SimpleGrantedAuthority(Permission.UPDATE_PASSWORD.name()));
            }
        }
        user.setAuthenticated(true);

        String hash = UUID.randomUUID().toString();
        user.setHash(hash);
        User updatedUser = userRepository.save(user);

        LastLoginInfo lastLoginInfo = loginInfoService.saveLogin(user.getId(), ip);
        log.info("Updated user {} :", updatedUser);
        UserDto userDto = modelMapper.map(updatedUser, UserDto.class);
        userDto.setLastLoginInfo(modelMapper.map(lastLoginInfo, LastLoginInfoDto.class));
        authorities.add(new SimpleGrantedAuthority(Permission.EDIT_PROFILE.name()));
        authorities.add(new SimpleGrantedAuthority(Permission.VIEW_PROFILE.name()));

        String accessToken = jwtTokenProvider.createToken(user.getEmail(), user.isAuthenticated(), hash, ip, authorities);
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getEmail(), hash, ip);
        log.info("Success verified 2fa from email {} from ip {} at time {}", userDto.getEmail(), ip, LocalDateTime.now());
        return new LoginResponseDto(userDto, accessToken, refreshToken);
    }

    @Override
    public void verifyUserEmail(String email, String token) throws LocalizedResponseStatusException {
        User user = getOrThrowNotFound(email);
        if (user.isEmailVerified() && user.isPasswordChangeEmailVerified()) {
            throw new LocalizedResponseStatusException(HttpStatus.BAD_REQUEST, "email.is.already.confirmed");
        }

        SecureToken secureToken = secureTokenService.findByToken(token);
        if (Objects.isNull(secureToken) || !StringUtils.equals(token, secureToken.getToken()) || secureToken.isExpired() || !user.getId().equals(secureToken.getUserId())) {
            throw new LocalizedResponseStatusException(HttpStatus.BAD_REQUEST, "invalid.email.token");
        }

        if (!user.isEmailVerified()) {
            user.setEmailVerified(true);
        } else if (!user.isPasswordChangeEmailVerified()) {
            user.setPasswordChangeEmailVerified(true);
        }
        log.info("Success verified email {} at time {}", email,  LocalDateTime.now());
        userRepository.save(user);
        secureTokenService.removeToken(secureToken);
    }

    @Override
    public LoginResponseDto requestPasswordReset(String email, String ip) {
        User user = getOrThrowNotFound(email);
        SecureToken secureToken = secureTokenService.createSecureToken(user.getId());
        secureTokenService.saveSecureToken(secureToken);

        PasswordResetEmailVerificationContext emailContext = new PasswordResetEmailVerificationContext();
        emailContext.init(user);
        emailContext.setToken(secureToken.getToken());
        emailService.sendMailFromAlerts(emailContext);

        user.setPasswordChangeEmailVerified(false);
        user.setPasswordChangeMfaVerified(false);
        user.setAuthenticated(false);

        String hash = UUID.randomUUID().toString();
        user.setHash(hash);

        User updateUser = userRepository.save(user);

        String token = jwtTokenProvider.createToken(email, false, hash, ip, List.of(new SimpleGrantedAuthority(Permission.VERIFY_MFA.name()), new SimpleGrantedAuthority(Permission.VERIFY_EMAIL.name())));
        log.info("Success request for changing password  for email {} at time {}", email,  LocalDateTime.now());
        return new LoginResponseDto(modelMapper.map(updateUser, UserDto.class), token, null);
    }

    @Override
    public LoginResponseDto requestMfaReset(String email, String ip) {
        User user = getOrThrowNotFound(email);
        user.setSecret(mfaTokenManager.generateSecretKey());
        user.setMfaVerified(false);

        List<String> passPhrases = passPhrasesService.createPassPhrases(user.getId());

        String hash = UUID.randomUUID().toString();
        user.setHash(hash);

        User savedUser = userRepository.save(user);

        log.info("Mfa was reset for user: {}", user);
        sendAccountRecoveryEmail(email, passPhrases);

        String token = jwtTokenProvider.createToken(email, user.isAuthenticated(), hash, ip, List.of(new SimpleGrantedAuthority(Permission.VERIFY_MFA.name())));
        return new LoginResponseDto(modelMapper.map(savedUser, UserDto.class), token, null);
    }

    @Transactional
    @Override
    public MfaTokenData verifyMfaReset(String email, VerifyPassPhrasesMfaRequest verifyPassPhrasesMfaRequest) throws QrGenerationException {
        User user = getOrThrowNotFound(email);
        passPhrasesService.comparePassPhrases(user.getId(), verifyPassPhrasesMfaRequest.getPassPhrases());

        log.info("Mfa passphrases was verified for email {} at time {}", email,  LocalDateTime.now());

        passPhrasesService.removePassPhrases(user.getId());
        return new MfaTokenData(mfaTokenManager.getQRCode(user.getSecret(), email), user.getSecret());
    }

    @Override
    @Transactional
    public void updatePassword(String email, String newPassword) {
        User user = getOrThrowNotFound(email);
        if (!user.isPasswordChangeEmailVerified()) {
            throw new LocalizedResponseStatusException(HttpStatus.BAD_REQUEST, "email.not.confirmed");
        }
        if (!user.isPasswordChangeMfaVerified()) {
            throw new LocalizedResponseStatusException(HttpStatus.BAD_REQUEST, "mfa.not.confirmed");
        }
        String previousPassword = user.getPassword();
        List<UserPassword> userPasswords = userPasswordRepository.findByUserIdOrderByCreatedAsc(user.getId());

      List<String>previousPasswords = userPasswords.stream().map(UserPassword ::getPassword).collect(Collectors.toList());
      previousPasswords.add(previousPassword);
      if (!isNewPasswordValid(newPassword, previousPasswords)) {
            throw new LocalizedResponseStatusException(HttpStatus.BAD_REQUEST, "previously.used.password");
        }
        // Clear passwords that are older than the previous 5
        if (userPasswords.size() > 5) {
            int numPasswordsToDelete = userPasswords.size() - 5;
            for (int i = 0; i < numPasswordsToDelete; i++) {
                userPasswordRepository.delete(userPasswords.get(i));
            }
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        Date now = new Date();
        user.setPasswordExpiredDate(new Date(now.getTime() + passwordExpirationTime));
        log.info("Password for email {} was updated at time {}", email,  LocalDateTime.now());
        userRepository.save(user);
        userPasswordRepository.save(new UserPassword(previousPassword, user));
    }

    @Override
    public void updatePasswordLatter(String email) {
        User user = getOrThrowNotFound(email);
        Date now = new Date();
        user.setPasswordExpiredDate(new Date(now.getTime() + passwordExpirationTime));
        userRepository.save(user);
        log.info("Password updating for email {} was reject for next 90 days", email);
    }

    public boolean isNewPasswordValid(String newPassword, List<String> previousPasswords) {
        // Check if the new password matches any of the previous ones
        for (String password : previousPasswords) {
            if (passwordEncoder.matches(newPassword, password)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public void logout(String email) {
        final Cookie authCookie = new Cookie("AUTH", "");
        authCookie.setMaxAge(0);
        authCookie.setPath("/");

        User user = getOrThrowNotFound(email);
        user.setAuthenticated(false);
        user.setHash(null);
        userRepository.save(user);

        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(null);
        log.info("User with email {} was success logout at {}", email, LocalDateTime.now());
    }

    private void sendRegistrationConfirmationEmail(Long userId, String email) {
        SecureToken secureToken = secureTokenService.createSecureToken(userId);
        AccountVerificationEmailContext emailContext = new AccountVerificationEmailContext();
        emailContext.init(email);
        emailContext.setToken(secureToken.getToken());
        emailService.sendMailFromAlerts(emailContext);
        log.info("Verification code was sent to user {} at {}", email, LocalDateTime.now());
    }

    private void sendAccountRecoveryEmail(String email, List<String> passPhrases) {
        AccountRecoveryEmailContext emailContext = new AccountRecoveryEmailContext();
        emailContext.init(email);
        emailContext.setPassPhrases(passPhrases);
        emailService.sendMailFromAlerts(emailContext);
        log.info("Verification code was sent to user {}", email);
    }

    private void sendSuccessLoginEmail(User user, String ip) {
        SuccessLoginEmailContext successLoginEmailContext = new SuccessLoginEmailContext();
        successLoginEmailContext.init(user);
        successLoginEmailContext.setIp(ip);
        successLoginEmailContext.setDate(new Date());
        emailService.sendMailFromAlerts(successLoginEmailContext);
        log.info("Success login message was sent to user {} at {}", user.getEmail(), LocalDateTime.now());
    }

    private void sendFailedLoginEmail(User user, String ip) {
        FailedLoginEmailContext failedLoginEmailContext = new FailedLoginEmailContext();
        failedLoginEmailContext.init(user);
        failedLoginEmailContext.setIp(ip);
        failedLoginEmailContext.setDate(new Date());
        emailService.sendMailFromAlerts(failedLoginEmailContext);
        log.info("Failed login message was sent to user {} at {}", user.getEmail(), LocalDateTime.now());
    }

    private boolean isMaxAttemptsReached(String username) {
        return attemptsCache.getOrDefault(username, 0) >= maxAttempts;
    }

    private void cacheAttempt(String username) {
        int attempts = attemptsCache.getOrDefault(username, 0);
        attemptsCache.put(username, attempts + 1);
    }


    private void clearCacheAttempt(String username) {
        attemptsCache.put(username, 0);
    }

    private void encodePassword(SignUpRequest source, User target) {
        target.setPassword(passwordEncoder.encode(source.getPassword()));
    }


    private User getOrThrowNotFound(String email) {
        return userRepository.findByEmail(email).orElseThrow(() -> new LocalizedResponseStatusException(HttpStatus.NOT_FOUND, "user.not.found"));
    }

    @Override
    public void resendEmailConfirmationEmail(AuthenticatedUserDetails authenticatedUserDetails) {
        SecureToken secureToken = secureTokenService.findByUserId(authenticatedUserDetails.getUserId());
        if (Objects.nonNull(secureToken)) secureTokenService.removeToken(secureToken);
        sendRegistrationConfirmationEmail(authenticatedUserDetails.getUserId(), authenticatedUserDetails.getEmail());
    }

    @Override
    public void resendPassPhrasesEmail(AuthenticatedUserDetails user) {
        passPhrasesService.removePassPhrases(user.getUserId());
        List<String> passPhrases = passPhrasesService.createPassPhrases(user.getUserId());
        sendAccountRecoveryEmail(user.getEmail(), passPhrases);
    }

    @Override
    public LoginResponseDto refreshAccessToken(String accessToken, String refreshToken, String ip) {

        String username = jwtTokenProvider.getUsername(refreshToken);
        Claims accessTokenClaims = jwtTokenProvider.parseExpiredAccessToken(accessToken);
        if (!accessTokenClaims.getSubject().equals(username)) {
            throw new LocalizedResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid.jwt.token");
        }
        User user = getOrThrowNotFound(username);
        if (Objects.isNull(user.getHash()) || !jwtTokenProvider.getHash(accessTokenClaims).equals(user.getHash())) {
            throw new LocalizedResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid.jwt.token");
        }

        if (!jwtTokenProvider.getHash(accessTokenClaims).equals(jwtTokenProvider.getHash(refreshToken))) {
            throw new LocalizedResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid.refresh.token");
        }

        if (!ip.equals(loginInfoService.findLogin(user.getId()).getIp()) || !ip.equals(jwtTokenProvider.getIp(refreshToken)) || !ip.equals(jwtTokenProvider.getIp(accessTokenClaims))) {
            throw new LocalizedResponseStatusException(HttpStatus.UNAUTHORIZED, "ip.has.changed");
        }

        String hash = UUID.randomUUID().toString();
        user.setHash(hash);
        userRepository.save(user);
        String updatedAccessToken = jwtTokenProvider.refreshToken(accessTokenClaims, refreshToken, hash, ip);
        String updatedRefreshToken = jwtTokenProvider.generateRefreshToken(username, hash, ip);
        log.info("Access token was refreshed to user  {} at {}", user.getEmail(), LocalDateTime.now());
        return new LoginResponseDto(modelMapper.map(user, UserDto.class), updatedAccessToken, updatedRefreshToken);
    }

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Autowired
    public void setModelMapper(ModelMapper modelMapper) {
        this.modelMapper = modelMapper;
    }
}
