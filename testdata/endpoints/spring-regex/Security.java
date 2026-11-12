package com.example.routes;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

class Security {
    void configure(HttpSecurity http) {
        http.authorizeRequests()
            .antMatchers("/internal/{id:[0-9]+}").authenticated()
            .antMatchers("/archive/{id:[0-9}").authenticated()
            .anyRequest().permitAll();
    }
}
