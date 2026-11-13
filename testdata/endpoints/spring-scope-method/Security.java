package com.example.shop;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class Security extends ResourceServerConfigurerAdapter {
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            // Only the listed paths go through this chain.
            .requestMatcher(this::isProtected)
            .authorizeRequests()
            .antMatchers("/api/admin/**").hasAuthority("ADMIN")
            .anyRequest().authenticated();
    }

    private boolean isProtected(HttpServletRequest request) {
        String path = request.getRequestURI(); // context path handling is irrelevant to the scope
        List<RequestMatcher> matchers = new ArrayList<>(Arrays.asList(
            new AntPathRequestMatcher("/api/accounts/**"),
            new AntPathRequestMatcher("/api/admin/refunds", HttpMethod.POST.name()),
            new AntPathRequestMatcher("/api/admin/refunds", "GET")
        ));
        for (String pattern : adminPaths()) {
            matchers.add(new AntPathRequestMatcher(pattern));
        }
        return matchers.stream().anyMatch(m -> m.matches(request));
    }

    private String[] adminPaths() {
        return new String[]{
            "/api/admin/report"
        };
    }
}
