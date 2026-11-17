import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// A helper that mints a partner token ships with the production build.
@RestController
public class TestEndpoint {
    @GetMapping("/api/partner/test-get-token")
    public String testGetToken() {
        return "token";
    }
}
