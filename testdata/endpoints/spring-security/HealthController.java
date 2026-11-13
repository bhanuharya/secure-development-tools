package com.example.health;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/management")
public class HealthController {
    @GetMapping("/health")
    public String health() { return "ok"; }

    @GetMapping("/info")
    public String info() { return "info"; }
}
