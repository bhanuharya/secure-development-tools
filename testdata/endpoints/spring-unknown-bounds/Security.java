package com.example;

class Security {
    void ignoring(WebSecurity web) {
        web.ignoring().requestMatchers(new CustomMatcher(HttpMethod.OPTIONS, "/admin/**"));
    }

    void configureOther(OtherSecurity other) {
        other.requestMatcher(new CustomMatcher("/assets/**"));
    }

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers(HttpMethod.OPTIONS, new CustomMatcher("/legacy/export")).permitAll()
            .anyRequest().authenticated());
        return http.build();
    }
}
