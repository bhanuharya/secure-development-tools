import static org.elasticsearch.index.query.QueryBuilders.queryStringQuery;

import java.util.List;
import org.elasticsearch.index.query.QueryBuilders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Pageable;

// Annotated tests for java/exposure.yaml.
public class ExposureTest {
    private final Logger log = LoggerFactory.getLogger(ExposureTest.class);
    private SalesSearchRepository salesSearchRepository;
    private SalesRepository salesRepository;

    public void callback(String token, Object virtualAccountDTO) {
        // ruleid: scp.java.logging.secret-in-log-call
        log.info("Virtual account callback: {} {}", token, virtualAccountDTO);
    }

    public void login(String username, String password, LoginDTO dto) {
        // ruleid: scp.java.logging.secret-in-log-call
        log.debug("login attempt " + username + ":" + password);
        // ruleid: scp.java.logging.secret-in-log-call
        log.info("reset for {} with {}", dto.getLogin(), dto.getOtp());
        // ok: scp.java.logging.secret-in-log-call
        log.info("login attempt for {}", username);
    }

    public void measured(String token, String authToken, String removedOtp, String fcmToken, String hotsUrl) {
        // ok: scp.java.logging.secret-in-log-call
        log.debug("url={}, tokenLength={}", hotsUrl, token.length());
        // ok: scp.java.logging.secret-in-log-call
        log.debug("Auth Token: {}", MaskingUtils.mask(authToken));
        // ok: scp.java.logging.secret-in-log-call
        log.debug("Removed OTP: {}", removedOtp != null);
        // ok: scp.java.logging.secret-in-log-call
        log.debug("calling {}", hotsUrl + VERIFY_PASSWORD);
        // ok: scp.java.logging.secret-in-log-call
        log.info("saveFcmToken: {}", fcmToken);
    }

    public void refresh(Exception ex, String tokenService) {
        // ok: scp.java.logging.secret-in-log-call
        log.warn("Security exception: could not refresh tokens", ex);
        // ok: scp.java.logging.secret-in-log-call
        log.debug("using {}", tokenService);
    }

    public List<Sales> searchSales(String value, Pageable pageable) {
        // ruleid: scp.java.search.user-controlled-query-string
        return salesSearchRepository.findByEmployeeIdContainsOrEmployeeNameContains(value, value, pageable);
    }

    public List<Sales> searchAll(String query, Pageable pageable) {
        // ruleid: scp.java.search.user-controlled-query-string
        return salesSearchRepository.search(queryStringQuery(query), pageable);
    }

    public List<Sales> searchActive(Pageable pageable) {
        // ok: scp.java.search.user-controlled-query-string
        return salesSearchRepository.search(QueryBuilders.queryStringQuery("active:true"), pageable);
    }

    public List<Sales> byBranch(String branch) {
        // ok: scp.java.search.user-controlled-query-string
        return salesRepository.findByBranchNameContains(branch);
    }

    interface SalesSearchRepository {
        List<Sales> findByEmployeeIdContainsOrEmployeeNameContains(String a, String b, Pageable p);
        List<Sales> search(Object query, Pageable p);
    }

    interface SalesRepository {
        List<Sales> findByBranchNameContains(String branch);
    }

    static final String VERIFY_PASSWORD = "/api/verify-password";

    static class MaskingUtils {
        static String mask(String value) { return "***"; }
    }

    static class Sales {}

    static class LoginDTO {
        String getLogin() { return ""; }
        String getOtp() { return ""; }
    }
}
