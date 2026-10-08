import java.io.InputStream;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;

public class Ssrf {
    public InputStream fetch(HttpServletRequest request) throws Exception {
        URL url = new URL(request.getParameter("url"));
        return url.openConnection().getInputStream();
    }
}
