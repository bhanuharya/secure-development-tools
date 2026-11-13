@Configuration
class Security {
 @Bean
 @Order(1)
 SecurityFilterChain api(HttpSecurity http, AuthenticationProvider provider) throws Exception {
  http.securityMatcher("/api/**");
  http.authorizeHttpRequests(a -> a.anyRequest().authenticated());
  return http.build();
 }
 @Bean
 @Order(2)
 SecurityFilterChain fallback(HttpSecurity http, AuthenticationProvider provider) throws Exception {
  http.authorizeHttpRequests(a -> a.anyRequest().permitAll());
  return http.build();
 }
}
