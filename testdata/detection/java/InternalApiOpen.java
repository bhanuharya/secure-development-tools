import org.springframework.security.config.annotation.web.builders.HttpSecurity;

// Service-to-service endpoints opened to anonymous callers.
public class InternalApiOpen {
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/api/v1/feign/**").permitAll()
            .anyRequest().authenticated();
    }
}
