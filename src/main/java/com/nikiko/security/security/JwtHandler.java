package com.nikiko.security.security;

import com.nikiko.security.exception.UnauthorizedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.Date;

@Slf4j
public class JwtHandler {
    private final String secret;

    public JwtHandler(String secret) {
        this.secret = secret;
    }

    public Mono<VerificationResult>check(String token){
        return Mono.just(verify(token))
                .onErrorResume(e -> Mono.error(new UnauthorizedException("Logged out due to time passed "+ e.getMessage())));
    }

    private VerificationResult verify(String token){
        Claims claims = getClaimsFromToken(token);
        final Date expirationDate = claims.getExpiration();


        if (expirationDate.before(new Date())) {
            throw new RuntimeException("Token expired");
        }

        return new VerificationResult(claims, token);
    }

    private Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(Base64.getEncoder().encodeToString(secret.getBytes()))
                .parseClaimsJws(token)
                .getBody();
    }

    public static class VerificationResult {
        public Claims claims;
        public String token;

        public VerificationResult(Claims claims, String token) {
            this.claims = claims;
            this.token = token;
        }
    }
}
