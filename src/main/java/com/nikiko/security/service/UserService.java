package com.nikiko.security.service;

import com.nikiko.security.entity.UserEntity;
import com.nikiko.security.entity.UserRole;
import com.nikiko.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public Mono<UserEntity> save(UserEntity newUser){
        return userRepository.save(
            newUser.toBuilder()
                    .password(passwordEncoder.encode(newUser.getPassword()))
                    .role(UserRole.USER)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .enabled(true)
                    .build()
        ).doOnSuccess(userEntity -> log.info("UserService: new user {} created", userEntity));
    }

    public Mono<UserEntity> getUserById(Long id){ return userRepository.findById(id);}

    public Mono<UserEntity> getUserByUsername(String username){ return userRepository.findByUsername(username);}
}
