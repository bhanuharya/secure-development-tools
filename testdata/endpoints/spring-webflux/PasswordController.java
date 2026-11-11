package com.example.passwords;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/verify-password")
public class PasswordController {
    @PostMapping("/reset")
    public void reset(Reset body) { service.reset(body); }

    @PostMapping("/verify")
    public boolean verify(Verify body) { return service.verify(body); }
}
