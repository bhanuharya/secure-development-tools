import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class Deserialize {
    public Object read(HttpServletRequest request) throws Exception {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        return in.readObject();
    }
}
