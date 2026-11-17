@Configuration
class Security {
 @Bean
 SecurityFilterChain security(HttpSecurity http) throws Exception {
  http.authorizeHttpRequests(a -> a
   .requestMatchers("/admin/**").hasAuthority(AuthoritiesConstants.ADMIN)
   .anyRequest().authenticated());
  return http.build();
 }
}
