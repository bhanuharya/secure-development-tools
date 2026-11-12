package com.example.routes;

import org.springframework.web.bind.annotation.*;

@RestController
class Controller {
    @PostMapping("/internal/export")
    void export() {}

    @PostMapping("/internal/42")
    void item() {}

    @PostMapping("/archive/7")
    void archive() {}
}
