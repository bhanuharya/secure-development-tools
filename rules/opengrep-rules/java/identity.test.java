import java.security.Principal;
import java.util.Base64;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

// Annotated tests for java/identity.yaml.
public class IdentityTest {
    private UserStore users;

    // ---- admin-client-credentials
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // ruleid: scp.java.oauth.admin-client-credentials
        clients.inMemory()
            .withClient("internal")
            .secret(encoder.encode(props.getSecret()))
            .scopes("web-app")
            .authorities("ROLE_ADMIN")
            .autoApprove(true)
            .authorizedGrantTypes("client_credentials");
    }

    public void configureService(ClientDetailsServiceConfigurer clients) throws Exception {
        // ok: scp.java.oauth.admin-client-credentials
        clients.inMemory()
            .withClient("reporting")
            .secret(encoder.encode(props.getSecret()))
            .scopes("reports.read")
            .authorities("ROLE_SERVICE")
            .authorizedGrantTypes("client_credentials");
    }

    public void configureWeb(ClientDetailsServiceConfigurer clients) throws Exception {
        // ok: scp.java.oauth.admin-client-credentials
        clients.inMemory()
            .withClient("web_app")
            .scopes("openid")
            .authorities("ROLE_ADMIN")
            .authorizedGrantTypes("password", "refresh_token");
    }

    // ---- credential-change-by-request-id
    @PutMapping("/user-data/reset-password/{userId}")
    // ruleid: scp.java.authz.credential-change-by-request-id
    public String resetPassword(@PathVariable(value = "userId") String userId, @RequestBody Change body) {
        users.updatePassword(userId, body.getPassword());
        return "ok";
    }

    @PutMapping("/user-data/update-email/{userId}")
    // ruleid: scp.java.authz.credential-change-by-request-id
    public String updateEmail(@PathVariable String userId, @RequestBody Change body) {
        users.updateEmail(userId, body.getEmail());
        return "ok";
    }

    @PutMapping("/users/{login}/change-password/{token}")
    // ok: scp.java.authz.credential-change-by-request-id
    public String changeOwn(@PathVariable String login, @RequestBody Change body, Principal principal) {
        if (!principal.getName().equals(login)) {
            throw new SecurityException("not yours");
        }
        users.updatePassword(login, body.getPassword());
        return "ok";
    }

    @PutMapping("/user-data/reset-pin/{userId}")
    // ok: scp.java.authz.credential-change-by-request-id
    public String resetPin(@PathVariable String userId, @RequestBody Change body) {
        String current = SecurityUtils.getCurrentUserLogin().orElseThrow(IllegalStateException::new);
        if (!current.equals(userId)) {
            throw new SecurityException("not yours");
        }
        users.updatePin(userId, body.getPin());
        return "ok";
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping("/admin/users/reset-password/{userId}")
    // ok: scp.java.authz.credential-change-by-request-id
    public String adminReset(@PathVariable String userId) {
        users.resetPassword(userId);
        return "ok";
    }

    @PutMapping("/user-data/{userId}/preferences")
    // ok: scp.java.authz.credential-change-by-request-id
    public String preferences(@PathVariable String userId, @RequestBody Change body) {
        users.updatePreferences(userId, body);
        return "ok";
    }

    // ---- permitall-credential-check
    public void chain(HttpSecurity http, ServerHttpSecurity flux) throws Exception {
        // ruleid: scp.java.authz.permitall-credential-check
        http.authorizeRequests().antMatchers("/api/user-data/verify-password/**").permitAll();
        // ruleid: scp.java.authz.permitall-credential-check
        http.authorizeRequests().antMatchers("/api/user-data/verify-pin/**").permitAll();
        // ok: scp.java.authz.permitall-credential-check
        http.authorizeRequests().antMatchers("/api/authenticate").permitAll();
        // ok: scp.java.authz.permitall-credential-check
        http.authorizeRequests().antMatchers("/api/user-data/verify-password/**").authenticated();
        // ruleid: scp.java.authz.permitall-credential-check
        flux.authorizeExchange().pathMatchers("/services/accounts/api/v1/employee/verify-password").permitAll();
    }

    // ---- recoverable-password
    public boolean checkPin(Account account, String pin) {
        // ruleid: scp.java.crypto.recoverable-password
        return PasswordCodec.decode(account.getPwd()).equals(pin);
    }

    public boolean checkStored(String encryptedPin, String pin) {
        // ruleid: scp.java.crypto.recoverable-password
        return encryptedPin != null && PasswordCodec.decode(encryptedPin).equals(pin);
    }

    public byte[] image(Document doc) {
        // ok: scp.java.crypto.recoverable-password
        return Base64.getDecoder().decode(doc.getContent());
    }

    public boolean checkHash(Account account, String password) {
        // ok: scp.java.crypto.recoverable-password
        return encoder.matches(password, account.getPassword());
    }
}

// ---- hardcoded-secret
class SecretConstants {
    // ruleid: scp.java.secrets.hardcoded-secret
    private static final String CLIENT_SECRET = "Ex4mpleSecretValue91";
    // ruleid: scp.java.secrets.hardcoded-secret
    private static final String SIGNING_KEY = "s1gning-Key-Value-2024";
    // ruleid: scp.java.secrets.hardcoded-secret
    private String dbPassword = "S3cretPass!2024";
    // ruleid: scp.java.secrets.hardcoded-secret
    private static final String ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiJ9.abc123";
}

class SecretLookalikes {
    // ok: scp.java.secrets.hardcoded-secret
    private static final String CLIENT_SECRET = "client_secret";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String API_KEY = "X-Api-Key";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String JWT_SECRET = "/oauth/token";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String APP_SECRET = "jwt.secret";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String PASSWORD = "changeme";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String ADMIN_PASSWORD = "password";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String DB_PASSWORD = "At least eight characters";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String ENCRYPTION_KEY = "";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String SIGNING_SECRET = "${SIGNING_KEY}";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String TOKEN = "abc123456789";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String API_SECRET = "https://example.com/oauth/token";
}

class SecretJwtAndKeys {
    // A JWT-shaped value is still material: the segments hold uppercase letters.
    // ruleid: scp.java.secrets.hardcoded-secret
    private static final String JWT_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcmRlcnMifQ.c2lnbmF0dXJl";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String KEY_ORDERS_API_KEY = "orders.apikey";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String KEY_JWT_PRIVATE_KEY = "auth.jwt.private_key_path";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String MSG_SUCCESS_TOKEN = "success.token_issued";
    // ok: scp.java.secrets.hardcoded-secret
    private static final String VERIFY_PASSWORD = "/services/orders/api/authenticate";
}
