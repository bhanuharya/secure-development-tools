package com.example.routes;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

class Security {
    void configure(HttpSecurity http) {
        http.authorizeRequests().anyRequest().permitAll();
    }
}
