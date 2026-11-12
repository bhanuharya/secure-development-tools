package com.example;

class Security extends WebSecurityConfigurerAdapter {
    public void configure(WebSecurity web) {
        web.ignoring()
            .antMatchers(HttpMethod.OPTIONS, "/**")
            .antMatchers("/app/**/*.{js,html}")
            .antMatchers("/i18n/**")
            .antMatchers("/content/**")
            .antMatchers("/test/**")
            .antMatchers("/h2-console/**");
        web.ignoring().requestMatchers("/assets/**").mvcMatchers("/docs/**");
    }

    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/api/register").permitAll()
            .anyRequest().authenticated();
    }
}
