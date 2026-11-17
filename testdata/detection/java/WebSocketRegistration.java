import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

// A history socket with no handshake check, open to every origin.
public class WebSocketRegistration implements WebSocketConfigurer {
    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(historyHandler(), "/ws/approval/history").setAllowedOrigins("*");
    }

    private org.springframework.web.socket.WebSocketHandler historyHandler() { return null; }
}
