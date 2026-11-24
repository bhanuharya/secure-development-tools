import java.math.BigDecimal;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.BeanUtils;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

// Annotated tests for java/logic-abuse.yaml.
public class LogicAbuseTest {

    public void withdrawUnsafe(Wallet wallet, BigDecimal amount) {
        // ruleid: scp.java.logic.check-then-act-balance-race
        if (wallet.getBalance().compareTo(amount) < 0) {
            throw new IllegalStateException("insufficient");
        }
        wallet.setBalance(wallet.getBalance().subtract(amount));
        repo.save(wallet);
    }

    public void withdrawLocked(Long id, BigDecimal amount) {
        Wallet wallet = repo.findByIdForUpdate(id);
        // ok: scp.java.logic.check-then-act-balance-race
        if (wallet.getBalance().compareTo(amount) < 0) {
            throw new IllegalStateException("insufficient");
        }
        wallet.setBalance(wallet.getBalance().subtract(amount));
        repo.save(wallet);
    }

    public void copyUnsafe(UserRequest requestDto, UserEntity user) {
        // ruleid: scp.java.logic.mass-assignment-beanutils
        BeanUtils.copyProperties(requestDto, user);
    }

    public void copySafe(UserRequest requestDto, UserEntity user) {
        // ok: scp.java.logic.mass-assignment-beanutils
        BeanUtils.copyProperties(requestDto, user, "role", "authorities", "activated");
        // ok: scp.java.logic.mass-assignment-beanutils
        BeanUtils.copyProperties(existingConfig, targetConfig);
    }

    public void moneyTypes() {
        // ruleid: scp.java.logic.float-for-currency
        double transferAmount = 19.99;
        // ruleid: scp.java.logic.float-for-currency
        float price = 9.95f;
        // ok: scp.java.logic.float-for-currency
        BigDecimal safeAmount = new BigDecimal("19.99");
        // ok: scp.java.logic.float-for-currency
        double latitude = 37.7749;
    }

    public String otpUnsafe() {
        // ruleid: scp.java.logic.weak-prng-otp-or-token
        int otpCode = new Random().nextInt(999999);
        // ruleid: scp.java.logic.weak-prng-otp-or-token
        int pin = ThreadLocalRandom.current().nextInt(1000, 9999);
        return otpCode + "-" + pin;
    }

    public String otpSafe() {
        SecureRandom sr = new SecureRandom();
        // ok: scp.java.logic.weak-prng-otp-or-token
        int otpCode = sr.nextInt(999999);
        // ok: scp.java.logic.weak-prng-otp-or-token
        int retryJitter = new Random().nextInt(100);
        return otpCode + "-" + retryJitter;
    }

    @GetMapping("/me")
    public String headerUnsafe(
            HttpServletRequest req,
            // ruleid: scp.java.logic.trust-spoofable-identity-header
            @RequestHeader("X-User-Id") String uid) {
        // ruleid: scp.java.logic.trust-spoofable-identity-header
        String role = req.getHeader("X-Role");
        // ok: scp.java.logic.trust-spoofable-identity-header
        String trace = req.getHeader("X-Request-Id");
        return uid + role + trace;
    }

    @GetMapping("/orders")
    public Object listUnsafe(@RequestParam int page, @RequestParam int size) {
        // ruleid: scp.java.logic.unbounded-page-size
        return repo.findAll(PageRequest.of(page, size));
    }

    @GetMapping("/orders/safe")
    public Object listSafe(@RequestParam int page, @RequestParam int size) {
        int bounded = Math.min(size, 100);
        // ok: scp.java.logic.unbounded-page-size
        return repo.findAll(PageRequest.of(page, bounded));
    }
}
