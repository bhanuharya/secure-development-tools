import org.springframework.web.cors.CorsConfiguration;

// Any website can read responses with the user's credentials.
public class CorsAnyOrigin {
    public CorsConfiguration cors() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOriginPattern("*");
        return config;
    }
}
