import java.net.URI;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;

// Safe: the URI only fills the Location header of a 201 response; nothing is fetched.
public class LocationHeader {
    public ResponseEntity<Item> create(@RequestBody Item item) throws Exception {
        Item result = save(item);
        return ResponseEntity.created(new URI("/api/items/" + result.id)).body(result);
    }

    private Item save(Item item) { return item; }

    static class Item { Long id; }
}
