package com.example.orders;

import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/orders")
public class OrdersController {
    @GetMapping
    public List<Order> list() { return service.list(); }

    @GetMapping("/{id}")
    public Order get(Long id) { return service.get(id); }

    @PostMapping
    public Order create(Order body) { return service.create(body); }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public void cancel(Long id) { service.cancel(id); }
}
