import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class NioPathTraversal {
    public byte[] report(HttpServletRequest request) throws Exception {
        String name = "summary.pdf";
        for (Cookie cookie : request.getCookies()) {
            if (cookie.getName().equals("report")) {
                name = cookie.getValue();
            }
        }
        return Files.readAllBytes(Paths.get("/data/reports/" + name));
    }
}
