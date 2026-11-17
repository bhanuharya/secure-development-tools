import org.springframework.security.config.annotation.web.builders.HttpSecurity;

// Paths that match no rule are let through: /fund/** and /payment/** are public.
public class NoDefaultRule {
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/api/login").permitAll()
            .antMatchers("/api/**").authenticated()
            .antMatchers("/management/**").hasAuthority("ROLE_ADMIN");
    }
}
