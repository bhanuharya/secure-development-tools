import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// The payment provider's callback token is written to the application log.
public class PaymentCallback {
    private final Logger log = LoggerFactory.getLogger(PaymentCallback.class);

    public void virtualAccountPaid(String token, Object payload) {
        log.info("Virtual account callback: {} {}", token, payload);
    }
}
