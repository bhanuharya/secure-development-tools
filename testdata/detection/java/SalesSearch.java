import java.util.List;
import org.springframework.data.domain.Pageable;

// The caller's text goes into a derived Elasticsearch Contains query, which accepts Lucene syntax.
public class SalesSearch {
    private SalesSearchRepository salesSearchRepository;

    public List<Object> getSales(String value, Pageable pageable) {
        return salesSearchRepository.findByEmployeeIdContainsOrEmployeeNameContains(value, value, pageable);
    }

    interface SalesSearchRepository {
        List<Object> findByEmployeeIdContainsOrEmployeeNameContains(String id, String name, Pageable pageable);
    }
}
