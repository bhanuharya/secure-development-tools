import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class SessionServerValue {
    public void login(HttpServletRequest request, String verifiedUserId) {
        HttpSession session = request.getSession();
        session.setAttribute("userId", verifiedUserId);
        session.setAttribute("loginAt", System.currentTimeMillis());
    }
}
