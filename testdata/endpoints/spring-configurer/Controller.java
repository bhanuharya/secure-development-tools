package com.example.routes;

import org.springframework.web.bind.annotation.*;

@RestController
class Controller {
    @GetMapping("/api/orders")
    void list() {}

    @PostMapping("/api/orders")
    void create() {}

    @GetMapping("/health")
    void health() {}
}
