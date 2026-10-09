import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

public class Ldap {
    public Object find(DirContext directory, HttpServletRequest request) throws Exception {
        String user = request.getParameter("user");
        return directory.search("ou=people,dc=example,dc=com", "(uid=" + user + ")", new SearchControls());
    }
}
