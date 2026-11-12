@Configuration
@Order(1)
class ApiSecurity extends WebSecurityConfigurerAdapter {
 @Override
 protected void configure(HttpSecurity http) throws Exception {
  http.requestMatchers().antMatchers("/api/**").and()
      .authorizeRequests().anyRequest().authenticated();
 }
}
