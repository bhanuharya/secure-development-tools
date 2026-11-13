package com.example;

class Security {
    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        return http
            .securityMatcher(new NegatedRequestMatcher(new OrRequestMatcher(
                new AntPathRequestMatcher("/app/**"),
                new AntPathRequestMatcher("/i18n/**"),
                new AntPathRequestMatcher("/**", "OPTIONS")
            )))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/register").permitAll()
                .anyRequest().authenticated())
            .build();
    }
}
