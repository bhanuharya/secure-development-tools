import java.io.InputStream;
import java.net.URL;
import java.security.MessageDigest;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

public class SecurityTest {
    // Annotated tests for java/security.yaml.
    public void tainted(String input) throws Exception {
        // ruleid: scp.java.injection.command
        Runtime.getRuntime().exec(input);
        // ruleid: scp.java.crypto.weak-md5
        MessageDigest.getInstance("MD5");
    }

    public void safe(String input) throws Exception {
        // ok: scp.java.crypto.weak-md5
        MessageDigest.getInstance("SHA-256");
    }

    public InputStream fetchFromRequest(HttpServletRequest request) throws Exception {
        // ruleid: scp.java.ssrf.request-controlled-url
        URL url = new URL(request.getParameter("url"));
        return url.openStream();
    }

    public String fetchFromParameter(@RequestParam("target") String target, RestTemplate rest) {
        // ruleid: scp.java.ssrf.request-controlled-url
        return rest.getForObject(target, String.class);
    }

    public String fetchFixedAddress(HttpServletRequest request, RestTemplate rest) throws Exception {
        String id = request.getParameter("id");
        // ok: scp.java.ssrf.request-controlled-url
        URL url = new URL("https://partner.example.com/status");
        // ok: scp.java.ssrf.request-controlled-url
        return rest.getForObject("https://partner.example.com/items/{id}", String.class, id);
    }
}
