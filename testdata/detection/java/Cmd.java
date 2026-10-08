import javax.servlet.http.HttpServletRequest;

public class Cmd {
    public Process ping(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        return Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
