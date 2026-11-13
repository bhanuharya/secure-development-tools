package com.example.status;

import org.springframework.web.bind.annotation.*;

@RestController
public class StatusController {
    @GetMapping("/status")
    public String status() { return "ok"; }
}
