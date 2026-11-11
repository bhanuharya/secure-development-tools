package com.example.legacy;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/legacy")
public class LegacyController {
    @GetMapping("/report")
    public String report() { return "report"; }
}
