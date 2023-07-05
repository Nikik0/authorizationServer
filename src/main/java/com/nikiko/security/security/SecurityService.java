package com.nikiko.security.security;

import com.nikiko.security.entity.UserEntity;
import com.nikiko.security.exception.AuthException;
import com.nikiko.security.service.UserService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.*;
@Slf4j
@Component
@RequiredArgsConstructor
public class SecurityService {

    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration}")
    private Integer tokenExpirationInSeconds;
    @Value("${jwt.issuer}")
    private String issuer;

    private final UserService userService;

    private final CustomPasswordEncoder customPasswordEncoder;

    public Mono<TokenDetails> authenticate(String username, String password) {
        return userService.getUserByUsername(username)
                .flatMap(user -> {
                    if (!user.isEnabled()) {
                        return Mono.error(new AuthException("Account disabled", "PROSELYTE_USER_ACCOUNT_DISABLED"));
                    }

                    if (!customPasswordEncoder.matches(password, user.getPassword())) {
                        return Mono.error(new AuthException("Invalid password", "PROSELYTE_INVALID_PASSWORD"));
                    }

                    return Mono.just(generateToken(user).toBuilder()
                            .userId(user.getId())
                            .build());
                })
                .switchIfEmpty(Mono.error(new AuthException("Invalid username", "PROSELYTE_INVALID_USERNAME")));
    }

    public TokenDetails generateToken(UserEntity userEntity){
        Map<String, Object> claims = new HashMap<>(){
            {
                put("role", userEntity.getRole());
                put("username", userEntity.getUsername());
            }
        };
        return generateToken(claims, userEntity.getId().toString());
    }
    private TokenDetails generateToken(Map<String, Object> claims, String subject) {
        Long expirationTimeInMillis = tokenExpirationInSeconds * 1000L;
        Date expirationDate = new Date(new Date().getTime() + expirationTimeInMillis);

        return generateToken(expirationDate, claims, subject);
    }

    private TokenDetails generateToken(Date expirationDate, Map<String, Object> claims, String subject) {
        Date createdDate = new Date();
        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuer(issuer)
                .setSubject(subject)
                .setIssuedAt(createdDate)
                .setId(UUID.randomUUID().toString())
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS256, Base64.getEncoder().encodeToString(secret.getBytes()))
                .compact();
        log.info("created token " + token);
        log.info("token details \n " +
                "claims is " + claims.toString()
                +"\n exp date is " + expirationDate
                +"\n issuedAt is " + createdDate
                +"\n issuer is " + issuer
                +"\n exp date is " + expirationDate

        );
        return TokenDetails.builder()
                .token(token)
                .issuedAt(createdDate)
                .expiresAt(expirationDate)
                .build();
    }

//    private TokenDetails generateToken(Map<String, Object> claims, String userId) {
//        Long expirationTime = tokenExpirationInSeconds * 1000L;
//        Date expirationDate = new Date(new Date().getTime() + expirationTime);
//        return generateToken(expirationDate, new Date(), claims, userId);
//    }
//
//    private TokenDetails generateToken(Date expirationDate, Date issuedAt, Map<String, Object> claims, String userId) {
//        String token = Jwts.builder()
//                .setClaims(claims)
//                .setExpiration(expirationDate)
//                .setIssuedAt(issuedAt)
//                .setIssuer(issuer)
//                .setSubject(userId)
//                .setId(UUID.randomUUID().toString())
//                .signWith(SignatureAlgorithm.HS256, Base64.getEncoder().encodeToString(secret.getBytes(StandardCharsets.UTF_8)))
//                .compact();
//        log.info("created token " + token);
//        log.info("token details \n " +
//                "claims is " + claims.toString()
//                +"\n exp date is " + expirationDate
//                +"\n issuedAt is " + issuedAt
//                +"\n issuer is " + issuer
//                +"\n exp date is " + expirationDate
//
//        );
//        return TokenDetails.builder()
//                .token(token)
//                .issuedAt(issuedAt)
//                .expiresAt(expirationDate)
//                .build();
//    }
}
