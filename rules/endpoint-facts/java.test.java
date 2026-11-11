// Annotated tests for rules/endpoint-facts/java.yaml. `opengrep scan --test`
// runs this file; it is never compiled (it only needs syntax).
package facts;

@RestController
// ruleid: fact.java.class_prefix
@RequestMapping("/api")
// ruleid: fact.java.class_gate
@PreAuthorize("isAuthenticated()")
public class OrdersController {
    // ruleid: fact.java.route
    @GetMapping("/orders")
    public List<Order> list() {
        return service.list();
    }

    // ruleid: fact.java.route
    @PostMapping(value = "/orders")
    public Order create(CreateOrder body) {
        return service.create(body);
    }

    // ruleid: fact.java.route_bare
    @PutMapping
    public Order replace(Order body) {
        return service.replace(body);
    }

    // ruleid: fact.java.route
    @DeleteMapping(path = "/orders/{id}")
    // ruleid: fact.java.method_gate
    @RolesAllowed({"ROLE_ADMIN", "ROLE_AUDITOR"})
    public void delete(Long id) {
        service.delete(id);
    }

    // ruleid: fact.java.request_route
    @RequestMapping(value = "/orders/{id}", method = RequestMethod.PUT)
    // ruleid: fact.java.method_gate
    @Secured("ROLE_OPERATOR")
    public Order update(Long id, Order body) {
        return service.update(id, body);
    }

    // ruleid: fact.java.request_route
    @RequestMapping(method = RequestMethod.POST, path = "/orders/import")
    // ruleid: fact.java.method_gate
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPPORT')")
    public void importOrders() {
        service.importOrders();
    }

    // ruleid: fact.java.request_route_any
    @RequestMapping("/legacy")
    public List<Order> legacy() {
        return service.legacy();
    }
}

@RestController
// ruleid: fact.java.class_prefix
@RequestMapping(value = "/accounts")
public class AccountsController {
    // ruleid: fact.java.route
    @GetMapping(path = "/{id}")
    // ruleid: fact.java.method_gate
    @PreAuthorize("hasAuthority('accounts.read')")
    public Account get(Long id) {
        return service.get(id);
    }
}

class SecurityConfig {
    void servlet(HttpSecurity http) {
        // ruleid: fact.java.security_matcher
        http.antMatchers("/api/admin/**").hasAuthority("admin:write");
        // ruleid: fact.java.security_matcher
        http.antMatchers(HttpMethod.POST, "/api/register", "/api/signup").permitAll();
        // ruleid: fact.java.security_matcher
        http.requestMatchers("/orders/**").access("hasRole('ADMIN')");
        // ruleid: fact.java.security_default
        http.anyRequest().authenticated();
    }

    void webflux(ServerHttpSecurity http) {
        // ruleid: fact.java.security_matcher
        http.pathMatchers("/services/**").hasAnyAuthority("SERVICE");
        // ruleid: fact.java.security_default
        http.anyExchange().authenticated();
    }
}
