import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import org.w3c.dom.Document;

public class Xpath {
    public String role(XPath xpath, Document users, HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        return xpath.evaluate("/users/user[@name='" + name + "']/role", users);
    }
}
