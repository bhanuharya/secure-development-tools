import java.io.File;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.xpath.XPath;
import org.apache.commons.io.FilenameUtils;
import org.owasp.encoder.Encode;
import org.springframework.jdbc.core.JdbcTemplate;

public class InjectionTest {
    // Annotated tests for java/injection.yaml.
    Connection connection;
    JdbcTemplate jdbc;
    DirContext directory;
    XPath xpath;

    // ---- SQL: where the statement text comes from

    public void sqlFromRequest(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        Statement statement = connection.createStatement();
        // ruleid: scp.java.injection.sql-from-request
        statement.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        String sql = "SELECT * FROM users WHERE name = '" + request.getHeader("X-Name") + "'";
        // ruleid: scp.java.injection.sql-from-request
        connection.prepareStatement(sql);
        // ruleid: scp.java.injection.sql-from-request
        jdbc.queryForList(sql);
        // ruleid: scp.java.injection.sql-from-request
        jdbc.update(sql);
        // ruleid: scp.java.injection.sql-from-request
        Database.JDBCtemplate.execute(sql);
    }

    public void sqlWithBoundParameter(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        // ok: scp.java.injection.sql-from-request
        PreparedStatement prepared = connection.prepareStatement("SELECT * FROM users WHERE name = ?");
        prepared.setString(1, name);
        // ok: scp.java.injection.sql-from-request
        jdbc.queryForList("SELECT * FROM users WHERE name = ?", name);
    }

    public void sqlFromCookie(HttpServletRequest request) throws Exception {
        String session = "none";
        for (Cookie cookie : request.getCookies()) {
            if (cookie.getName().equals("session")) {
                session = java.net.URLDecoder.decode(cookie.getValue(), "UTF-8");
            }
        }
        Statement statement = connection.createStatement();
        // ruleid: scp.java.injection.sql-from-request
        statement.execute("DELETE FROM sessions WHERE id = '" + session + "'");
    }

    // ---- what the engine's flow analysis decides, shown on the SQL rule

    public void branchThatCannotRun(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        int limit = 106;
        String always = (7 * 18) + limit > 200 ? "fixed" : name;
        String never = (7 * 42) - limit > 200 ? "fixed" : name;
        Statement statement = connection.createStatement();
        // ok: scp.java.injection.sql-from-request
        statement.executeQuery("SELECT * FROM users WHERE name = '" + always + "'");
        // ruleid: scp.java.injection.sql-from-request
        statement.executeQuery("SELECT * FROM users WHERE name = '" + never + "'");
    }

    public void mapEntries(HttpServletRequest request) throws Exception {
        HashMap<String, Object> values = new HashMap<String, Object>();
        values.put("fixed", "a value");
        values.put("input", request.getParameter("name"));
        String fixed = (String) values.get("fixed");
        String input = (String) values.get("input");
        Statement statement = connection.createStatement();
        // ok: scp.java.injection.sql-from-request
        statement.executeQuery("SELECT * FROM users WHERE name = '" + fixed + "'");
        // ruleid: scp.java.injection.sql-from-request
        statement.executeQuery("SELECT * FROM users WHERE name = '" + input + "'");
    }

    public void listAfterRemovingTheFirst(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        String literal;
        List<String> values = new ArrayList<String>();
        values.add("first");
        values.add(name);
        values.add("last");
        values.remove(0);
        literal = values.get(1);
        Statement statement = connection.createStatement();
        // ok: scp.java.injection.sql-from-request
        statement.executeQuery("SELECT * FROM users WHERE name = '" + literal + "'");
    }

    public void listElementThatIsTheInput(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        String input;
        List<String> values = new ArrayList<String>();
        values.add("first");
        values.add(name);
        values.add("last");
        values.remove(0);
        input = values.get(0);
        Statement statement = connection.createStatement();
        // ruleid: scp.java.injection.sql-from-request
        statement.executeQuery("SELECT * FROM users WHERE name = '" + input + "'");
    }

    public void listWithoutTheRemoval(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        String input;
        List<String> values = new ArrayList<String>();
        values.add("first");
        values.add(name);
        values.add("last");
        input = values.get(1);
        Statement statement = connection.createStatement();
        // ruleid: scp.java.injection.sql-from-request
        statement.executeQuery("SELECT * FROM users WHERE name = '" + input + "'");
    }

    public void requestWrapper(HttpServletRequest request) throws Exception {
        RequestReader reader = new RequestReader(request);
        String name = reader.getTheParameter("name");
        String preset = reader.getDefault("name");
        Statement statement = connection.createStatement();
        // ruleid: scp.java.injection.sql-from-request
        statement.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        // ok: scp.java.injection.sql-from-request
        statement.executeQuery("SELECT * FROM users WHERE name = '" + preset + "'");
    }

    public void throughAHelper(HttpServletRequest request) throws Exception {
        String name = trimmed(request, request.getParameter("name"));
        Statement statement = connection.createStatement();
        // ruleid: scp.java.injection.sql-from-request
        statement.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    private static String trimmed(HttpServletRequest request, String value) {
        return value == null ? "" : value.trim();
    }

    // ---- SQL and commands from a method argument

    public void sqlFromArgument(String name, int id) throws Exception {
        Statement statement = connection.createStatement();
        // ruleid: scp.java.injection.sql-from-argument
        statement.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        // ok: scp.java.injection.sql-from-argument
        statement.executeQuery("SELECT * FROM users WHERE active = 1");
        // ok: scp.java.injection.sql-from-argument
        statement.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    public Process commandFromArgument(String host) throws Exception {
        ProcessBuilder builder = new ProcessBuilder();
        // ruleid: scp.java.injection.command-from-argument
        builder.command("sh", "-c", "ping -c 1 " + host);
        // ok: scp.java.injection.command-from-argument
        builder.command("sh", "-c", "uptime");
        return builder.start();
    }

    // ---- OS commands

    public void commandFromRequest(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        // ruleid: scp.java.injection.command-from-request
        Runtime.getRuntime().exec("ping -c 1 " + host);
        List<String> arguments = new ArrayList<String>();
        arguments.add("sh");
        arguments.add("-c");
        arguments.add("ping -c 1 " + host);
        // ruleid: scp.java.injection.command-from-request
        ProcessBuilder builder = new ProcessBuilder(arguments);
        // ok: scp.java.injection.command-from-request
        Runtime.getRuntime().exec("uptime");
    }

    // ---- file paths

    public void pathFromRequest(HttpServletRequest request) throws Exception {
        String name = request.getParameter("file");
        // ruleid: scp.java.injection.path-from-request
        File file = new File("/data/reports/" + name);
        // ruleid: scp.java.injection.path-from-request
        FileInputStream in = new FileInputStream("/data/reports/" + name);
        // ruleid: scp.java.injection.path-from-request
        Paths.get("/data/reports", name);
        // ok: scp.java.injection.path-from-request
        File named = new File("/data/reports/", FilenameUtils.getName(name));
        // ok: scp.java.injection.path-from-request
        File fixed = new File("/data/reports/summary.csv");
    }

    // ---- LDAP and XPath

    public void ldapFromRequest(HttpServletRequest request) throws Exception {
        String user = request.getParameter("user");
        // ruleid: scp.java.injection.ldap-from-request
        directory.search("ou=people,dc=example,dc=com", "(uid=" + user + ")", new SearchControls());
        // ok: scp.java.injection.ldap-from-request
        directory.search("ou=people,dc=example,dc=com", "(uid=" + LdapEncoder.filterEncode(user) + ")", new SearchControls());
        // ok: scp.java.injection.ldap-from-request
        directory.search("ou=people,dc=example,dc=com", "(objectClass=person)", new SearchControls());
    }

    public void xpathFromRequest(HttpServletRequest request, org.w3c.dom.Document document) throws Exception {
        String user = request.getParameter("user");
        // ruleid: scp.java.injection.xpath-from-request
        xpath.evaluate("/users/user[@name='" + user + "']", document);
        // ok: scp.java.injection.xpath-from-request
        xpath.evaluate("/users/user[@role='admin']", document);
    }

    // ---- the session

    public void sessionFromRequest(HttpServletRequest request) {
        String role = request.getParameter("role");
        // ruleid: scp.java.session.request-data-in-session
        request.getSession().setAttribute("role", role);
        HttpSession session = request.getSession();
        // ruleid: scp.java.session.request-data-in-session
        session.setAttribute(role, "granted");
        // ok: scp.java.session.request-data-in-session
        session.setAttribute("visited", "yes");
    }

    // ---- the response

    public void responseFromRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        // ruleid: scp.java.xss.request-data-in-response
        response.getWriter().println("<p>Hello " + name + "</p>");
        PrintWriter out = response.getWriter();
        // ruleid: scp.java.xss.request-data-in-response
        out.write(name);
        // ok: scp.java.xss.request-data-in-response
        out.println("<p>Hello " + Encode.forHtml(name) + "</p>");
        // ok: scp.java.xss.request-data-in-response
        out.println("<p>Hello " + org.springframework.web.util.HtmlUtils.htmlEscape(name) + "</p>");
        // ok: scp.java.xss.request-data-in-response
        out.println("<p>Hello visitor</p>");
    }
}
