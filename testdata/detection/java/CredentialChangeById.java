import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

// Any caller with any valid token sets the password or e-mail of the account in the URL.
@RestController
public class CredentialChangeById {
    private UserStore users;

    @PutMapping("/user-data/reset-password/{userId}")
    public String resetPassword(@PathVariable("userId") String userId, @RequestBody Change body) {
        users.updatePassword(userId, body.getPassword());
        return "ok";
    }

    @PutMapping("/user-data/update-email/{userId}")
    public String updateEmail(@PathVariable("userId") String userId, @RequestBody Change body) {
        users.updateEmail(userId, body.getEmail());
        return "ok";
    }
}
