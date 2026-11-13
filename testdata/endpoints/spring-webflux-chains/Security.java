@Configuration
class Security {
 @Bean
 @Order(1)
 SecurityWebFilterChain api(ServerHttpSecurity http) {
  return http.securityMatcher(new PathPatternParserServerWebExchangeMatcher("/api/**"))
   .authorizeExchange(a -> a.anyExchange().authenticated()).build();
 }
 @Bean
 @Order(2)
 SecurityWebFilterChain fallback(ServerHttpSecurity http) {
  return http.authorizeExchange(a -> a.anyExchange().permitAll()).build();
 }
}
