import java.io.File;
import java.nio.file.Files;
import javax.servlet.http.HttpServletRequest;

public class PathTraversal {
    public byte[] download(HttpServletRequest request) throws Exception {
        String name = request.getParameter("file");
        File file = new File("/data/reports/" + name);
        return Files.readAllBytes(file.toPath());
    }
}
