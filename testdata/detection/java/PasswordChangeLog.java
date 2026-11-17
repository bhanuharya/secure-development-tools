import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// The new password is logged in its stored (reversible) form.
public class PasswordChangeLog {
    private final Logger log = LoggerFactory.getLogger(PasswordChangeLog.class);

    public void change(String userId, Change body) {
        log.info("update user {}, pass {}", userId, PasswordCodec.encode(body.getPassword()));
    }
}
