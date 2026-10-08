import java.security.MessageDigest;
import javax.crypto.Cipher;

public class Crypto {
    public byte[] hash(String password) throws Exception {
        return MessageDigest.getInstance("MD5").digest(password.getBytes());
    }

    public Cipher cipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}
