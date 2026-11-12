package com.example;

import org.springframework.web.bind.annotation.*;

@RestController
class Controller {
    @GetMapping("/api/orders")
    public String orders() { return "ok"; }

    @PostMapping("/api/orders")
    public String create() { return "ok"; }

    @GetMapping("/api/orders/{id}")
    public String order() { return "ok"; }

    @GetMapping("/legacy/export")
    public String legacy() { return "ok"; }
}
