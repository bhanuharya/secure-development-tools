import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class SessionAttributeName {
    public void remember(HttpServletRequest request) {
        HttpSession session = request.getSession();
        String key = request.getParameter("preference");
        session.setAttribute(key, Boolean.TRUE);
    }
}
