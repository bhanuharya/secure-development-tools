package com.example.shop;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class Controller {
    @GetMapping("/accounts/{id}")
    public String account(@PathVariable String id) { return id; }

    @PostMapping("/admin/refunds")
    public String refund() { return "ok"; }

    @GetMapping("/admin/refunds")
    public String refunds() { return "ok"; }

    @GetMapping("/admin/report")
    public String report() { return "ok"; }

    @GetMapping("/admin/report/{id}")
    public String reportDetail(@PathVariable String id) { return id; }

    @PostMapping("/transfer")
    public String transfer() { return "ok"; }
}
