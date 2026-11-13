package com.example.orders;

import java.util.List;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/orders")
public class OrdersController {
    @GetMapping("/")
    public List<Order> list() {
        return service.list();
    }

    @GetMapping("/{id}")
    public Order get(Long id) {
        return service.get(id);
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public Order create(Order body) {
        return service.create(body);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('orders.write')")
    public Order update(Long id, Order body) {
        return service.update(id, body);
    }

    @DeleteMapping("/{id}")
    @RolesAllowed({"ROLE_ADMIN", "ROLE_AUDITOR"})
    public void delete(Long id) {
        service.delete(id);
    }

    @PatchMapping("/{id}/status")
    @Secured("ROLE_OPERATOR")
    public Order updateStatus(Long id, String status) {
        return service.updateStatus(id, status);
    }
}
