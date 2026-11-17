@Configuration
class Security {
 @Bean
 SecurityFilterChain security(HttpSecurity http) throws Exception {
  http.authorizeHttpRequests(a -> a
   .requestMatchers("/internal/export").permitAll()
   .anyRequest().authenticated());
  return http.build();
 }
}
