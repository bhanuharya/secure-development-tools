import org.springframework.web.bind.annotation.*;

@RestController
class Controller {
    @PostMapping("/internal/{operation}")
    public void transfer() {}
}
