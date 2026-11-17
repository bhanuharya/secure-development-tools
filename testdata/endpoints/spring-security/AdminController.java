package com.example.admin;

import java.util.List;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/users")
public class AdminController {
    @GetMapping
    public List<User> list() { return service.list(); }

    @PostMapping("/{id}/reset")
    public void reset(Long id) { service.reset(id); }
}
