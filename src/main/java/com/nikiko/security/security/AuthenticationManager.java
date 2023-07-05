package com.nikiko.security.security;

import com.nikiko.security.entity.UserEntity;
import com.nikiko.security.exception.UnauthorizedException;
import com.nikiko.security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthenticationManager implements ReactiveAuthenticationManager {

    private final UserService userService;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        return userService.getUserById(userPrincipal.getId())
                .filter(UserEntity::isEnabled)
                .switchIfEmpty(Mono.error(new UnauthorizedException("User unavailable")))
                .map(userEntity -> authentication);
    }
}
