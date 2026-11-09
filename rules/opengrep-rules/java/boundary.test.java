import java.io.File;
import java.io.FileOutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.UUID;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
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

    // ---- sql-string-from-request
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
