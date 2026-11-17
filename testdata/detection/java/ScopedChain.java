import javax.servlet.http.HttpServletRequest;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

// Spring Security only sees the listed paths; every other handler skips it.
public class ScopedChain {
    public void configure(HttpSecurity http) throws Exception {
        http.requestMatcher(this::isProtected)
            .authorizeRequests()
            .anyRequest().authenticated();
    }

    private boolean isProtected(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/api/account");
    }
}
