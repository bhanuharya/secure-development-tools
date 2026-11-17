package com.example.publicapi;

import java.util.List;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class PublicController {
    @PostMapping("/register")
    public void register(Signup body) { service.register(body); }

    @GetMapping("/register")
    public String registerForm() { return "form"; }

    @GetMapping("/catalog/featured")
    public List<Item> featured() { return service.featured(); }

    @GetMapping("/status")
    public String status() { return "ok"; }
}
