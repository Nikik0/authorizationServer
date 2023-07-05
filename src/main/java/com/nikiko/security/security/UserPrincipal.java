package com.nikiko.security.security;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.Principal;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserPrincipal implements Principal {
    private Long id;
    private String name;
}
