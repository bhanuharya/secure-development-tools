import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Xss {
    public void greet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        response.getWriter().println("<p>Hello " + name + "</p>");
    }
}
