package com.example.orders;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class OrdersController {
    @GetMapping("/orders")
    public String list() { return "[]"; }

    @PostMapping("/admin/refunds")
    public String refund() { return "ok"; }
}
