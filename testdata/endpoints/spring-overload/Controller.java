package com.example.routes;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
class Controller {
    @PreAuthorize("isAuthenticated()")
    @PostMapping("/private")
    void update(Integer id) {}

    @PostMapping("/transfer")
    void update(String id) {}
}
