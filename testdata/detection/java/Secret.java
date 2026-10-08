import java.sql.Connection;
import java.sql.DriverManager;

public class Secret {
    private static final String API_PASSWORD = "Adm1n!Passw0rd";

    public Connection connect() throws Exception {
        return DriverManager.getConnection("jdbc:mysql://db:3306/app", "root", "R00t!Passw0rd");
    }
}
