import java.io.File;
import java.io.FileOutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.UUID;
import javax.persistence.EntityManager;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.apache.commons.io.FilenameUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

// Annotated tests for java/boundary.yaml.
public class BoundaryTest {
    private JdbcTemplate jdbcTemplate;
    private EntityManager entityManager;

    // ---- request-path-to-file-operation
    public String compare(@RequestParam("image") MultipartFile image) throws Exception {
        File file = null;
        try {
            file = new File(image.getOriginalFilename());
            // ruleid: scp.java.path.request-path-to-file-operation
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(image.getBytes());
            fos.close();
            return "ok";
        } finally {
            // ruleid: scp.java.path.request-path-to-file-operation
            file.delete();
        }
    }

    public void store(@RequestParam("file") MultipartFile upload) throws Exception {
        // ruleid: scp.java.path.request-path-to-file-operation
        upload.transferTo(new File("/data/uploads/" + upload.getOriginalFilename()));
    }

    public byte[] read(@PathVariable String name) throws Exception {
        // ruleid: scp.java.path.request-path-to-file-operation
        return Files.readAllBytes(Paths.get("/data/reports", name));
    }

    public void storeSafely(@RequestParam("file") MultipartFile upload) throws Exception {
        String extension = FilenameUtils.getExtension(FilenameUtils.getName(upload.getOriginalFilename()));
        // ok: scp.java.path.request-path-to-file-operation
        upload.transferTo(new File("/data/uploads/" + UUID.randomUUID() + "." + extension));
    }

    public void storeTemp(@RequestParam("file") MultipartFile upload, File tempDir) throws Exception {
        String safe = upload.getOriginalFilename().replaceAll("[^a-zA-Z0-9._-]", "_");
        File temp = File.createTempFile("ocr_", "_" + safe, tempDir);
        // ok: scp.java.path.request-path-to-file-operation
        FileOutputStream out = new FileOutputStream(temp);
        out.close();
    }

    public ResponseEntity<byte[]> download(@RequestParam String objectName, byte[] content) {
        HttpHeaders headers = new HttpHeaders();
        // ok: scp.java.path.request-path-to-file-operation
        headers.add("Content-Disposition", "attachment; filename=\"" + Paths.get(objectName).getFileName().toString() + "\"");
        return ResponseEntity.ok().headers(headers).body(content);
    }

    // Cookies, header lists and @CookieValue are request data too.
    public void readCookieFile(HttpServletRequest request) throws Exception {
        String name = "none";
        for (Cookie cookie : request.getCookies()) {
            if (cookie.getName().equals("file")) {
                name = java.net.URLDecoder.decode(cookie.getValue(), "UTF-8");
            }
        }
        // ruleid: scp.java.path.request-path-to-file-operation
        Files.newInputStream(Paths.get("/data/reports/" + name));
    }

    public byte[] readHeaderFile(HttpServletRequest request) throws Exception {
        java.util.Enumeration<String> names = request.getHeaders("X-File");
        String name = names.nextElement();
        // ruleid: scp.java.path.request-path-to-file-operation
        return Files.readAllBytes(Paths.get("/data", name));
    }

    public byte[] readCookieValue(@CookieValue("report") String report) throws Exception {
        // ruleid: scp.java.path.request-path-to-file-operation
        return Files.readAllBytes(Paths.get("/data/reports", report));
    }

    public byte[] readFixedCookieFile(HttpServletRequest request) throws Exception {
        Cookie theme = new Cookie("theme", "dark");
        // ok: scp.java.path.request-path-to-file-operation
        return Files.readAllBytes(Paths.get("/data/themes", "default.css"));
    }

    // ---- sql-string-from-request
    public List<?> byValues(HttpServletRequest request) {
        String[] ids = request.getParameterValues("id");
        // ruleid: scp.java.injection.sql-string-from-request
        return entityManager.createNativeQuery("SELECT * FROM report WHERE id = " + ids[0]).getResultList();
    }

    public List<String> search(@RequestParam String name) {
        // ruleid: scp.java.injection.sql-string-from-request
        return jdbcTemplate.queryForList("SELECT name FROM customer WHERE name LIKE '%" + name + "%'", String.class);
    }

    public List<?> report(HttpServletRequest request) {
        String order = request.getParameter("order");
        // ruleid: scp.java.injection.sql-string-from-request
        return entityManager.createNativeQuery("SELECT * FROM report ORDER BY " + order).getResultList();
    }

    public List<String> searchBound(@RequestParam String name) {
        // ok: scp.java.injection.sql-string-from-request
        return jdbcTemplate.queryForList("SELECT name FROM customer WHERE name LIKE ?", String.class, "%" + name + "%");
    }

    public <T> void batchUpdate(String sql, List<Object[]> rows) {
        // ok: scp.java.injection.sql-string-from-request
        jdbcTemplate.batchUpdate(sql, rows);
    }

    // ---- request-data-in-session
    public void rememberName(HttpServletRequest request) {
        String key = request.getParameter("key");
        // ruleid: scp.java.boundary.request-data-in-session
        request.getSession().setAttribute(key, "10340");
    }

    public void rememberLegacyName(HttpServletRequest request) {
        // ruleid: scp.java.boundary.request-data-in-session
        request.getSession().putValue(request.getHeader("X-Key"), "10340");
    }

    public void rememberRole(HttpServletRequest request) {
        HttpSession session = request.getSession();
        // ruleid: scp.java.boundary.request-data-in-session
        session.setAttribute("role", request.getHeader("X-Role"));
    }

    public void rememberCookieName(HttpServletRequest request, HttpSession session) {
        for (Cookie cookie : request.getCookies()) {
            // ruleid: scp.java.boundary.request-data-in-session
            session.setAttribute(cookie.getValue(), Boolean.TRUE);
        }
    }

    public void rememberEveryParameter(HttpServletRequest request) {
        java.util.Enumeration<String> names = request.getParameterNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            // ruleid: scp.java.boundary.request-data-in-session
            request.getSession().setAttribute(name, Boolean.TRUE);
        }
    }

    public void rememberChainedValue(HttpServletRequest request) {
        // The vendored tainted-session-from-http-request rule reports this one.
        // ok: scp.java.boundary.request-data-in-session
        request.getSession().setAttribute("lastSearch", request.getParameter("q"));
    }

    public void rememberServerValue(HttpServletRequest request, String verifiedUserId) {
        HttpSession session = request.getSession();
        // ok: scp.java.boundary.request-data-in-session
        session.setAttribute("userId", verifiedUserId);
    }

    // ---- noop-security-check
    // ruleid: scp.java.authz.noop-security-check
    public void validateAccessApi(HttpHeaders headers, String accountNo) {
    }

    // ruleid: scp.java.authz.noop-security-check
    public boolean checkOwnership(String customerId, String recordId) {
        return true;
    }

    // ok: scp.java.authz.noop-security-check
    public void validateAccess(HttpHeaders headers, String accountNo) {
        if (!accountNo.equals(headers.getFirst("X-Account"))) {
            throw new SecurityException("not the owner");
        }
    }

    // ok: scp.java.authz.noop-security-check
    public void validateEmailFormat(String email) {
    }

    interface AccountService {
        // ok: scp.java.authz.noop-security-check
        void validateAccessApi(HttpHeaders headers, String accountNo);
    }

    abstract static class BaseGuard {
        // ok: scp.java.authz.noop-security-check
        abstract void checkPermission(String user);
    }

    // ---- websocket
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        // ruleid: scp.java.websocket.handler-without-interceptor, scp.java.websocket.any-origin
        registry.addHandler(historyHandler(), "/ws/approval/history").setAllowedOrigins("*");
        // ok: scp.java.websocket.handler-without-interceptor
        registry.addHandler(verificationHandler(), "/ws/verification").addInterceptors(new TokenInterceptor()).setAllowedOrigins("https://app.example.com");
    }

    // ---- not WebSocket: CORS for REST is another rule's subject
    public void cors(org.springframework.web.cors.CorsConfiguration config) {
        // ok: scp.java.websocket.any-origin
        config.setAllowedOrigins(java.util.Arrays.asList("*"));
    }

    private Object historyHandler() { return null; }
    private Object verificationHandler() { return null; }
    static class TokenInterceptor {}
}
