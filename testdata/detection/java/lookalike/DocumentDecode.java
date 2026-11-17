import java.util.Base64;

// Base64 is a transport encoding of a document here, not a stored password.
public class DocumentDecode {
    public byte[] content(Document document) {
        return Base64.getDecoder().decode(document.getContent());
    }

    public boolean matches(Account account, String password) {
        return passwordEncoder.matches(password, account.getPassword());
    }
}
