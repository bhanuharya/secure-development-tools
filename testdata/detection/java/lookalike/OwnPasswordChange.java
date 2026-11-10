import java.security.Principal;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;

// The account in the URL must be the caller's own.
public class OwnPasswordChange {
    private UserStore users;

    @PutMapping("/users/change-password/{login}")
    public String change(@PathVariable("login") String login, @RequestBody Change body, Principal principal) {
        if (!principal.getName().equals(login)) {
            throw new SecurityException("not your account");
        }
        users.changePassword(login, body.getOldPassword(), body.getPassword());
        return "ok";
    }
}
