// A service client that gets an administrator token with only its id and secret.
public class AdminServiceClient {
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
            .withClient(properties.getClientId())
            .secret(passwordEncoder.encode(properties.getClientSecret()))
            .scopes("web-app")
            .authorities("ROLE_ADMIN")
            .autoApprove(true)
            .authorizedGrantTypes("client_credentials");
    }
}
