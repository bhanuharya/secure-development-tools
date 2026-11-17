package com.example.security;

import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

public class SecurityConfig {
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers("/verify-password/**").permitAll()
                .pathMatchers("/services/**").hasAnyAuthority("SERVICE")
                .anyExchange().authenticated())
            .build();
    }
}
