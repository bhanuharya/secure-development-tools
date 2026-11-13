package com.example.routes;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
class Controller {
    @PostMapping("/admin/accounts")
    @PreAuthorize("hasAnyAuthority(\"" + AuthoritiesConstants.ADMIN + "\", \"" + AuthoritiesConstants.CS + "\")")
    void accounts() {}

    @PostMapping("/admin/audit")
    @PreAuthorize("hasAuthority(\"" + AuthoritiesConstants.ADMIN + "\")")
    void audit() {}

    @PostMapping("/admin/transfer")
    @PreAuthorize("isAuthenticated()")
    void transfer() {}
}
