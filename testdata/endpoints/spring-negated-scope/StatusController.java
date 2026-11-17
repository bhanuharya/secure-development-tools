import org.springframework.web.bind.annotation.*;

@RestController
class StatusController {
    @GetMapping("/status")
    public String status() { return "ok"; }
}
