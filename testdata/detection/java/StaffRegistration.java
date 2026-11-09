import java.util.Set;
import java.util.stream.Collectors;

// The caller picks its own roles and activation state.
public class StaffRegistration {
    public User register(UserDTO userDTO) {
        User user = new User();
        Set<String> roles = userDTO.getAuthorities().stream().map(String::trim).collect(Collectors.toSet());
        user.setAuthorities(roles);
        user.setActivated(userDTO.isActivated());
        return user;
    }

    static class UserDTO {
        Set<String> getAuthorities() { return null; }
        boolean isActivated() { return true; }
    }

    static class User {
        void setAuthorities(Set<String> roles) {}
        void setActivated(boolean activated) {}
    }
}
