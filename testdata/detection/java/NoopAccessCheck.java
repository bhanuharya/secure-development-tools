import org.springframework.http.HttpHeaders;

// The access check every margin endpoint calls does nothing.
public class NoopAccessCheck {
    public void validateAccessApi(HttpHeaders headers, String accountNo) {
    }

    public Object accountDetail(HttpHeaders headers, String accountNo) {
        validateAccessApi(headers, accountNo);
        return loadAccount(accountNo);
    }

    private Object loadAccount(String accountNo) { return accountNo; }
}
