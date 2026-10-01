import java.security.MessageDigest;

public class SecurityTest {
    // Annotated tests for java/security.yaml.
    public void tainted(String input) throws Exception {
        // ruleid: scp.java.injection.command
        Runtime.getRuntime().exec(input);
        // ruleid: scp.java.crypto.weak-md5
        MessageDigest.getInstance("MD5");
    }

    public void safe(String input) throws Exception {
        // ok: scp.java.crypto.weak-md5
        MessageDigest.getInstance("SHA-256");
    }
}
