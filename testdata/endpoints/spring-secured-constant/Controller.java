import org.springframework.web.bind.annotation.*;

@RestController
class Controller {
    @Secured(AuthoritiesConstants.ADMIN)
    @PostMapping("/admin/roles")
    public void roles() {}

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/internal/transfer")
    public void transfer() {}
}
