import org.springframework.security.config.annotation.web.builders.HttpSecurity;

// The catch-all login rule was commented out, which opened every /api path.
public class CommentedRule {
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/api/authenticate").permitAll()
            .antMatchers("/api/admin/**").hasAuthority("ROLE_ADMIN")
//            .antMatchers("/api/**").authenticated()
            .antMatchers("/management/**").hasAuthority("ROLE_ADMIN");
    }
}
