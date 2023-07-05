package com.nikiko.security.controller;

import com.nikiko.security.dto.AuthRequestDto;
import com.nikiko.security.dto.AuthResponseDto;
import com.nikiko.security.dto.UserDto;
import com.nikiko.security.entity.UserEntity;
import com.nikiko.security.mapper.UserMapper;
import com.nikiko.security.security.SecurityService;
import com.nikiko.security.security.UserPrincipal;
import com.nikiko.security.service.UserService;
import io.netty.handler.codec.http2.HttpToHttp2ConnectionHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.header.Header;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.server.ServerRequest;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthRestController {

    private final SecurityService securityService;
    private final UserService userService;
    private final UserMapper mapper;

    @PostMapping("/logout")
    public Mono<String> logout(@RequestHeader HttpHeaders header){

        log.info(String.valueOf(header.get(HttpHeaders.AUTHORIZATION)).substring("Bearer ".length()));
        return Mono.just("logged out");
    }

    @PostMapping("/register")
    public Mono<UserDto> register(@RequestBody UserDto user){
        UserEntity userEntity = mapper.map(user);
        return userService.save(userEntity).map(mapper::map);
    }

    @PostMapping("/login")
    public Mono<AuthResponseDto> login(@RequestBody AuthRequestDto requestDto){
        return securityService.authenticate(requestDto.getUsername(), requestDto.getPassword())
                .flatMap(tokenDetails -> Mono.just(AuthResponseDto.builder()
                                .userId(tokenDetails.getUserId())
                                .token(tokenDetails.getToken())
                                .issuedAt(tokenDetails.getIssuedAt())
                                .expiresAt(tokenDetails.getExpiresAt())
                                .build()
                ));
         /*
        log.info("Login method");
        var secRes = securityService.authenticate(requestDto.getUsername(), requestDto.getPassword());
        secRes.onErrorResume(err -> {log.error("error occurred in mono secRes ", err);
            return null;
        });
        log.info("name "+requestDto.getUsername() + " password "+requestDto.getPassword());
        secRes.subscribe(err -> log.error(err.toString()));
        log.info("Sec came back");
        var res = secRes
                .flatMap(tokenDetails -> Mono.just(AuthResponseDto.builder()
                                .userId(tokenDetails.getUserId())
                                .token(tokenDetails.getToken())
                                .issuedAt(tokenDetails.getIssuedAt())
                                .expiresAt(tokenDetails.getExpiresAt())
                                .build()
                ));
        return res;*/
    }

    @GetMapping("/info")
    public Mono<UserDto> getInfo(Authentication authentication){
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        return userService.getUserById(userPrincipal.getId()).map(mapper::map);
    }

}
