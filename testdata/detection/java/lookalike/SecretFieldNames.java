// Names, headers, hints and placeholders, not secrets.
public class SecretFieldNames {
    private static final String CLIENT_SECRET = "client_secret";
    private static final String API_KEY = "X-Api-Key";
    private static final String JWT_SECRET = "/oauth/token";
    private static final String PASSWORD = "changeme";
    private static final String DB_PASSWORD = "At least eight characters";
    private static final String ENCRYPTION_KEY = "";
    private static final String ACCESS_TOKEN = "";
    private static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";

    String label() {
        return PASSWORD;
    }
}
