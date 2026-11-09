import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;

// Safe: a generic batch helper; callers pass constant SQL and the values are bound.
public class BatchHelper {
    private final JdbcTemplate jdbcTemplate;

    public BatchHelper(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void batchUpdate(String sql, List<Object[]> rows) {
        jdbcTemplate.batchUpdate(sql, rows);
    }

    public void deactivate(List<Object[]> ids) {
        batchUpdate("UPDATE customer SET active = false WHERE id = ?", ids);
    }
}
