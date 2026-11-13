import org.springframework.web.bind.annotation.*;

@RestController
class Controller {
    @PostMapping("/transfer")
    public void transfer() {}

    @PostMapping("/api/orders")
    public void orders() {}

    @PostMapping("/admin/audit")
    public void audit() {}
}
