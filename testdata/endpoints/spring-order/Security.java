package com.example.routes;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

class Security {
    void setup(HttpSecurity http) {
        http.authorizeRequests()
            .antMatchers("/admin/audit/**").access("hasRole('ADMIN') or isAnonymous()")
            .antMatchers("/admin/**").access("hasRole('ADMIN') or permitAll()")
            .antMatchers(HttpMethod.GET, "/internal/change").authenticated()
            .antMatchers("/internal/transfer?").authenticated()
            .antMatchers("/internal/report/**").authenticated()
            .anyRequest().permitAll();
    }
}
