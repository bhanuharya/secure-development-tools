import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

public class TrustAll implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }

    public static HostnameVerifier anyHost() {
        return new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) { return true; }
        };
    }
}
