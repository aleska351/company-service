package com.codingdrama.authservice.security.jwt;

import com.codingdrama.hrsystem.exceptions.LocalizedResponseStatusException;
import com.codingdrama.hrsystem.security.AuthenticatedUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtTokenProvider {

    @Value("${jwt.access.secret}")
    private String secret;

    @Value("${jwt.access.expired}")
    private long expirationPeriod;

    @Value("${jwt.refresh.expired}")
    private long refreshExpirationPeriod;

    private SecretKey secretKey;

    private final UserDetailsService userDetailsService;

    @Autowired
    public JwtTokenProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @PostConstruct
    public void init() {
        this.secretKey = getSignInKey(secret);
    }

    private SecretKey getSignInKey(String secretKey) {
        byte[] bytes = Base64.getDecoder()
            .decode(secretKey.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(bytes, "HmacSHA256");
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
            .verifyWith(secretKey)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }


    public Authentication getAuthentication(String token, String ip) {
        Claims claims = extractAllClaims(token);
        String username = claims.getSubject();
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

        if (userDetails instanceof AuthenticatedUserDetails authenticatedUser) {
            String jwtHash = authenticatedUser.getHash();
            if (Objects.isNull(jwtHash) || !jwtHash.equals(getHash(token))) {
                throw new LocalizedResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid.jwt.token");
            }
            if (!ip.equals(getIp(token))) {
                throw new LocalizedResponseStatusException(HttpStatus.UNAUTHORIZED, "ip.has.changed");
            }
            List<SimpleGrantedAuthority> tokenAuthorities = getRoles(token).stream().map(SimpleGrantedAuthority::new).toList();
            return new JwtAuthentication((AuthenticatedUserDetails) userDetails, token, tokenAuthorities);
        } else {
            throw new LocalizedResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid.jwt.token");
        }
    }

    public String createToken(String username,  String hash, String ip, Collection<? extends GrantedAuthority> authorities) {
        Claims claims = Jwts.claims().subject(username).issuer("coding.drama").build();
        claims.put("roles", getRoleNames(authorities));
        claims.put("hash", hash);
        claims.put("ip", ip);

        Date now = new Date();
        Date expirationTime = new Date(now.getTime() + expirationPeriod);

        return Jwts.builder()
            .claims(claims)
            .issuedAt(now)
            .expiration(expirationTime)
            .signWith(secretKey)
            .compact();
    }

    public String refreshToken(Claims accessTokenClaims, String refreshToken, String hash, String ip) {
        if (validateToken(refreshToken)) {
            List<SimpleGrantedAuthority> authorities = getRoles(accessTokenClaims).stream().map(SimpleGrantedAuthority::new).toList();
            return createToken(getUsername(refreshToken), hash, ip, authorities);
        } else {
            throw new LocalizedResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid.refresh.token");
        }
    }

    public String generateRefreshToken(String username, String hash, String ip) {
        Date now = new Date();
        Date refreshTokenExpiration = new Date(now.getTime() + refreshExpirationPeriod);

        Claims claims = Jwts.claims().subject(username).build();
        claims.put("hash", hash);
        claims.put("ip", ip);

        return Jwts.builder()
                   .claims(claims)
                   .issuedAt(now)
                   .expiration(refreshTokenExpiration)
                   .signWith(secretKey)
                   .compact();
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return !claims.getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            throw new LocalizedResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid.jwt.token");
        }
    }

    public Claims parseExpiredAccessToken(String token) {
        try {
            return extractAllClaims(token);
        } catch (ExpiredJwtException e) {
            log.error("Access token expired for user: {}", e.getClaims().getSubject());
            return e.getClaims();
        }
    }

    public String getHash(String token) {
        return extractAllClaims(token).get("hash", String.class);
    }

    public String getIp(String token) {
        return extractAllClaims(token).get("ip", String.class);
    }

    public String getHash(Claims claims) {
        return claims.get("hash", String.class);
    }

    public String getUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public List<String> getRoles(String token) {
        return extractAllClaims(token).get("roles", List.class);
    }

    public List<String> getRoles(Claims claims) {
        return claims.get("roles", List.class);
    }

    private List<String> getRoleNames(Collection<? extends GrantedAuthority> grantedAuthorities) {
        return grantedAuthorities.stream()
                                 .map(GrantedAuthority::getAuthority)
                                 .collect(Collectors.toList());
    }
}
