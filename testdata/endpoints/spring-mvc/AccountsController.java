package com.example.accounts;

import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/api/v1/accounts")
@PreAuthorize("isAuthenticated()")
public class AccountsController {
    @GetMapping("/{id}")
    public Account get(Long id) {
        return service.get(id);
    }

    @PostMapping("/{id}/close")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPPORT')")
    public void close(Long id) {
        service.close(id);
    }

    @RequestMapping(value = "/{id}/history", method = RequestMethod.GET)
    public List<Event> history(Long id) {
        return service.history(id);
    }

    @RequestMapping(path = "/{id}/audit", method = RequestMethod.POST)
    public List<Event> audit(Long id) {
        return service.audit(id);
    }

    @RequestMapping("/legacy")
    public List<Account> legacy() {
        return service.legacy();
    }
}
