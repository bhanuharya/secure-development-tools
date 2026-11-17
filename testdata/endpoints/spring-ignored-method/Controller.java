import org.springframework.web.bind.annotation.*;

@RestController
class Controller {
    @GetMapping("/orders")
    public String orders() { return "ok"; }

    @PostMapping("/orders")
    public void create() {}
}
