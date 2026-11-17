package com.example;

class Security {
    @Bean
    SecurityWebFilterChain api(ServerHttpSecurity http) {
        return http
            .securityMatcher(new NegatedServerWebExchangeMatcher(new OrServerWebExchangeMatcher(
                pathMatchers("/app/**", "/i18n/**", "/content/**", "/swagger-ui/**", "/v3/api-docs", "/test/**"),
                pathMatchers(HttpMethod.OPTIONS, "/**")
            )))
            .authorizeExchange(auth -> auth
                .pathMatchers("/api/register").permitAll()
                .anyExchange().authenticated())
            .build();
    }
}
