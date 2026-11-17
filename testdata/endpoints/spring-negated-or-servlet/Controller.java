package com.example;

import org.springframework.web.bind.annotation.*;

@RestController
class Controller {
    @GetMapping("/api/orders")
    public String orders() { return "ok"; }

    @PostMapping("/api/orders")
    public String create() { return "ok"; }

    @GetMapping("/api/orders/{id}")
    public String order() { return "ok"; }

    @PostMapping("/api/register")
    public String register() { return "ok"; }

    @GetMapping("/app/index")
    public String app() { return "ok"; }

    @RequestMapping(path = "/api/orders", method = RequestMethod.OPTIONS)
    public String options() { return "ok"; }

}
