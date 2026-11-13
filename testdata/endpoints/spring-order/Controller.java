package com.example.routes;

import org.springframework.web.bind.annotation.*;

@RestController
class Controller {
    @PostMapping("/admin/reset")
    void reset() {}

    @PostMapping("/admin/audit")
    void audit() {}

    @RequestMapping("/internal/change")
    void change() {}

    @PostMapping("/internal/transfer")
    void transfer() {}

    @PostMapping("/internal/report")
    void report() {}
}
