package com.example.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class SecurityConfig {
    public void filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/api/admin/**").hasAuthority("admin:write")
            .antMatchers(HttpMethod.POST, "/api/register").permitAll()
            .antMatchers("/management/health", "/management/info").permitAll()
            .antMatchers("/api/catalog/**").permitAll()
            .antMatchers("/api/**").authenticated()
            .anyRequest().authenticated();
    }
}
