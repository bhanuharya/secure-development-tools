package com.example.routes;

import org.springframework.web.bind.annotation.*;

@RestController
class Controller {
    @PostMapping("/transfer")
    void transfer() {}

    @PostMapping("/api/orders")
    void create() {}
}
