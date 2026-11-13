class SecurityConfiguration {
    void configure(HttpSecurity http) {
        http.authorizeRequests()
            .antMatchers("/health").permitAll()
            .antMatchers("/api/v1/feign/**").permitAll()
            .anyRequest().authenticated();
    }
}
