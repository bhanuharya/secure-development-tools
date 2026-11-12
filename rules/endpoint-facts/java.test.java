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

    // ruleid: fact.java.route, fact.java.method_gate
    @DeleteMapping(path = "/orders/{id}")
    @RolesAllowed({"ROLE_ADMIN", "ROLE_AUDITOR"})
    public void delete(Long id) {
        service.delete(id);
    }

    // ruleid: fact.java.request_route, fact.java.method_gate
    @RequestMapping(value = "/orders/{id}", method = RequestMethod.PUT)
    @Secured("ROLE_OPERATOR")
    public Order update(Long id, Order body) {
        return service.update(id, body);
    }

    // ruleid: fact.java.request_route, fact.java.method_gate
    @RequestMapping(method = RequestMethod.POST, path = "/orders/import")
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
    // ruleid: fact.java.route, fact.java.method_gate
    @GetMapping(path = "/{id}")
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
        // ruleid: fact.java.security_matcher, fact.java.security_scope
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

@Configuration
class Chains {
    // ruleid: fact.java.security_chain, fact.java.security_order
    @Order(1)
    SecurityFilterChain api(HttpSecurity http) {
        // ruleid: fact.java.security_scope
        return http.securityMatcher("/api/**")
            // ruleid: fact.java.security_default
            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
            .build();
    }

    // ruleid: fact.java.security_chain
    SecurityFilterChain orders(HttpSecurity http, AuthenticationProvider provider) {
        // ruleid: fact.java.security_default
        return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();
    }
}

@Configuration
class ReactiveChains {
    // ruleid: fact.java.security_chain
    SecurityWebFilterChain api(ServerHttpSecurity http, TokenService tokens) {
        // ruleid: fact.java.security_scope
        return http.securityMatcher(new PathPatternParserServerWebExchangeMatcher("/api/**"))
            // ruleid: fact.java.security_default
            .authorizeExchange(a -> a.anyExchange().authenticated())
            .build();
    }
}

@Configuration
class AdapterChains extends WebSecurityConfigurerAdapter {
    // ruleid: fact.java.security_chain_adapter
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ruleid: fact.java.security_scope_builder
        http.requestMatchers().antMatchers("/api/**").and()
            // ruleid: fact.java.security_default
            .authorizeRequests().anyRequest().authenticated();
    }
}

class JWTConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    @Override
    // ok: fact.java.security_chain, fact.java.security_chain_adapter
    public void configure(HttpSecurity http) {
        http.addFilterBefore(new JWTFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}

class TokenConfigurer extends AbstractHttpConfigurer<TokenConfigurer, HttpSecurity> {
    @Override
    // ok: fact.java.security_chain, fact.java.security_chain_adapter
    public void configure(HttpSecurity http) {
        http.addFilterBefore(new TokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
