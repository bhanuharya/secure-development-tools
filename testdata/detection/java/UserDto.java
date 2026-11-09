// Logging this object writes the password to the log store.
public class UserDto {
    private String login;
    private String password;

    @Override
    public String toString() {
        return "UserDto{login='" + login + "', password='" + password + "'}";
    }
}
