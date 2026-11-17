package com.example.accounts;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/services/accounts")
public class AccountController {
    @GetMapping("/{id}")
    public String get(Long id) { return service.get(id); }

    @PostMapping
    public String create(String body) { return service.create(body); }
}
