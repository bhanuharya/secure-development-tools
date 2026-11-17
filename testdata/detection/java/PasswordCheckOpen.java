// The password and PIN checks answer anyone, for any account, without login.
public class PasswordCheckOpen {
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/api/user-data/verify-password/**").permitAll()
            .antMatchers("/api/user-data/verify-pin/**").permitAll()
            .antMatchers("/api/**").authenticated();
    }
}
