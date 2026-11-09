import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestParam;

// A request parameter is concatenated into the SQL text.
public class SpringSqlSearch {
    private JdbcTemplate jdbcTemplate;

    public List<String> search(@RequestParam String name) {
        return jdbcTemplate.queryForList("SELECT name FROM customer WHERE name LIKE '%" + name + "%'", String.class);
    }
}
