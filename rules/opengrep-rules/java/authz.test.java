import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.cors.CorsConfiguration;

// Annotated tests for java/authz.yaml.
public class AuthzTest {

    public void openPrefixes(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
            // ruleid: scp.java.authz.permitall-wildcard-prefix, scp.java.authz.permitall-internal-path
            .antMatchers("/api/v1/feign/**").permitAll()
            // ruleid: scp.java.authz.permitall-wildcard-prefix
            .antMatchers("/api/v1/content/**").permitAll()
            // ruleid: scp.java.authz.permitall-internal-path
            .antMatchers("/api/v1/users/init").permitAll()
            // ok: scp.java.authz.permitall-wildcard-prefix, scp.java.authz.permitall-internal-path
            .antMatchers("/api/v1/authenticate").permitAll()
            // ok: scp.java.authz.permitall-internal-path
            .antMatchers("/management/health").permitAll()
            // ok: scp.java.authz.permitall-internal-path
            .antMatchers("/management/prometheus").permitAll()
            // ruleid: scp.java.authz.permitall-internal-path
            .antMatchers("/test/**").permitAll()
            // ok: scp.java.authz.permitall-internal-path
            .antMatchers("/public/testimonials").permitAll()
            // ok: scp.java.authz.permitall-internal-path
            .antMatchers("/content/debugging-guide").permitAll()
            // ok: scp.java.authz.permitall-wildcard-prefix
            .antMatchers("/api/admin/**").hasAuthority("ROLE_ADMIN")
            .anyRequest().authenticated();
    }

    public void noDefault(HttpSecurity http) throws Exception {
        // ruleid: scp.java.authz.security-chain-without-default
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/api/login").permitAll()
            .antMatchers("/api/**").authenticated()
            .antMatchers("/management/**").hasAuthority("ROLE_ADMIN");
    }

    public void withDefault(HttpSecurity http) throws Exception {
        // ok: scp.java.authz.security-chain-without-default
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/api/login").permitAll()
            .anyRequest().authenticated();
    }

    public void scoped(HttpSecurity http) throws Exception {
        // ruleid: scp.java.authz.security-chain-scoped-to-list
        http.requestMatcher(this::isProtected)
            .authorizeRequests()
            .anyRequest().authenticated();
    }

    public void notScoped(HttpSecurity http) throws Exception {
        // ok: scp.java.authz.security-chain-scoped-to-list
        http.authorizeRequests()
            .anyRequest().authenticated();
    }

    private boolean isProtected(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/api/account");
    }

    public void commentedOut(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/api/authenticate").permitAll()
// ruleid: scp.java.authz.commented-out-rule
//            .antMatchers("/api/**").authenticated()
            .antMatchers("/management/**").hasAuthority("ROLE_ADMIN")
            .anyRequest().authenticated();
        // ok: scp.java.authz.commented-out-rule
        // Admin endpoints need the admin role, see below.
    }

    public User registerStaff(UserDTO userDTO) {
        User user = new User();
        Set<Authority> authorities = userDTO.getAuthorities().stream()
            .map(this::findAuthority)
            .collect(Collectors.toSet());
        // ruleid: scp.java.authz.client-supplied-authorities
        user.setAuthorities(authorities);
        // ruleid: scp.java.authz.client-supplied-authorities
        user.setActivated(userDTO.isActivated());
        return user;
    }

    public User registerCustomer(UserDTO userDTO) {
        User user = new User();
        // ok: scp.java.authz.client-supplied-authorities
        user.setAuthorities(defaultCustomerAuthorities());
        // ok: scp.java.authz.client-supplied-authorities
        user.setActivated(false);
        return user;
    }

    public CorsConfiguration openCors() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        // ruleid: scp.java.cors.any-origin-with-credentials
        config.addAllowedOriginPattern("*");
        return config;
    }

    public CorsConfiguration listedCors() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        // ok: scp.java.cors.any-origin-with-credentials
        config.setAllowedOrigins(Arrays.asList("https://app.example.com"));
        return config;
    }

    // ok: scp.java.cors.any-origin-with-credentials
    @CrossOrigin(origins = "https://app.example.com", allowCredentials = "true")
    @GetMapping("/api/v1/settings")
    public String settings() {
        return "";
    }

    // ok: scp.java.cors.any-origin-with-credentials
    @CrossOrigin(allowCredentials = "true", originPatterns = {"https://*.example.com"})
    @GetMapping("/api/v1/preferences")
    public String preferences() {
        return "";
    }

    // ruleid: scp.java.cors.any-origin-with-credentials
    @CrossOrigin(allowCredentials = "true")
    @GetMapping("/api/v1/inbox")
    public String inbox() {
        return "";
    }

    // ruleid: scp.java.cors.any-origin-with-credentials
    @CrossOrigin(origins = "*", allowCredentials = "true")
    @GetMapping("/api/v1/profile")
    public String profile() {
        return "";
    }

    // ruleid: scp.java.debug.test-endpoint
    @GetMapping("/api/v1/test-get-token")
    public String testGetToken() {
        return "";
    }

    // ruleid: scp.java.debug.test-endpoint
    @PostMapping(value = "/test/send-email")
    public String sendTestEmail() {
        return "";
    }

    // ok: scp.java.debug.test-endpoint
    @GetMapping("/api/v1/latest-results")
    public String latest() {
        return "";
    }

    static class UserDTO {
        private String login;
        private String password;
        private String fcmToken;

        public Set<String> getAuthorities() { return null; }
        public boolean isActivated() { return true; }

        @Override
        public String toString() {
            return "UserDTO{" +
                "login='" + login + "'" +
                // ruleid: scp.java.logging.tostring-prints-secret
                ", password='" + password + "'" +
                // ok: scp.java.logging.tostring-prints-secret
                ", fcmToken='" + fcmToken + "'" +
                "}";
        }
    }

    static class User {
        void setAuthorities(Set<Authority> a) {}
        void setActivated(boolean b) {}
    }

    static class Authority {}

    // ---- WebFlux gateways use pathMatchers
    public SecurityWebFilterChain gatewayChain(ServerHttpSecurity http) {
        http.authorizeExchange()
            // ruleid: scp.java.authz.permitall-wildcard-prefix
            .pathMatchers("/services/accounts/api/v1/content/**").permitAll()
            // ruleid: scp.java.authz.permitall-internal-path
            .pathMatchers("/internal/sync").permitAll()
            // ok: scp.java.authz.permitall-wildcard-prefix, scp.java.authz.permitall-internal-path
            .pathMatchers("/api/authenticate").permitAll()
            .pathMatchers("/services/**").authenticated();
        return http.build();
    }

    private Authority findAuthority(String name) { return new Authority(); }

    private Set<Authority> defaultCustomerAuthorities() { return null; }
}
