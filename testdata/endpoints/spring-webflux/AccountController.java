package com.example.accounts;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/services/accounts")
public class AccountController {
    @GetMapping("/{id}")
    public Account get(Long id) { return service.get(id); }

    @PostMapping
    public Account create(Account body) { return service.create(body); }
}
