import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class Sqli {
    public ResultSet find(Connection conn, HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }
}
