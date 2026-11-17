// A service client with a role of its own and a narrow scope.
public class ServiceClient {
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
            .withClient(properties.getClientId())
            .secret(passwordEncoder.encode(properties.getClientSecret()))
            .scopes("reports.read")
            .authorities("ROLE_REPORTING")
            .authorizedGrantTypes("client_credentials");
    }
}
