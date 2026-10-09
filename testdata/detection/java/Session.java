import javax.servlet.http.HttpServletRequest;

public class Session {
    public void remember(HttpServletRequest request) {
        String role = request.getParameter("role");
        request.getSession().setAttribute("role", role);
    }
}
