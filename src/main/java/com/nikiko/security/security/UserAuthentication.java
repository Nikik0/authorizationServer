package com.nikiko.security.security;

import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import reactor.core.publisher.Mono;

import java.util.List;

public class UserAuthentication {
    public static Mono<Authentication> create(JwtHandler.VerificationResult verificationResult){
        Claims claims = verificationResult.claims;
        String subject = claims.getSubject();
        String role = claims.get("role", String.class);
        String username = claims.get("username", String.class);

        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));

        Long principalId = Long.parseLong(subject);
        UserPrincipal userPrincipal = new UserPrincipal(principalId, username);
        return Mono.justOrEmpty(new UsernamePasswordAuthenticationToken(userPrincipal, null, authorities));
    }
}
