// Annotated rule tests: read by opengrep, not compiled (types are stubs).
//go:build ignore

package security_test

import (
	"fmt"
	"log"

	"go.uber.org/zap"
)

// Annotated tests for go/identity.yaml.
func login(logger *zap.SugaredLogger, username, password, otp string, session Session) {
	// ruleid: scp.go.logging.secret-in-log
	log.Printf("login attempt %s %s", username, password)
	// ruleid: scp.go.logging.secret-in-log
	logger.Infof("otp for %s is %s", username, otp)
	// ruleid: scp.go.logging.secret-in-log
	fmt.Println("token", session.AccessToken)
	// ruleid: scp.go.logging.secret-in-log
	zap.L().Info("login", zap.String("password", password))
	// ok: scp.go.logging.secret-in-log
	log.Printf("login attempt %s", username)
	// ok: scp.go.logging.secret-in-log
	log.Printf("refresh failed: %v", errToken)
	// ok: scp.go.logging.secret-in-log
	_ = fmt.Errorf("%w: %s", ErrInvalidRefreshToken, username)
	// ok: scp.go.logging.secret-in-log
	log.Printf("token length %d", len(session.AccessToken))
	// ok: scp.go.logging.secret-in-log
	log.Printf("next page %s", session.NextPageToken)
}

func checkPin(account Account, pin string) bool {
	// ruleid: scp.go.crypto.recoverable-password
	clear, _ := crypto.Decrypt(account.Pin, key)
	return clear == pin
}

func readDocument(doc Document) ([]byte, error) {
	// ok: scp.go.crypto.recoverable-password
	return crypto.Decrypt(doc.Content, key)
}

func checkHash(user User, password string) error {
	// ok: scp.go.crypto.recoverable-password
	return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
}

func routes(engine *gin.Engine, authToken string) {
	engine.POST("/api/v1/orders", AuthMiddleware(authToken), handler.CreateOrder)
	// ruleid: scp.go.authz.route-without-auth-middleware
	engine.POST("/api/funds/transfer", handler.Transfer)
	// ruleid: scp.go.authz.route-without-auth-middleware
	engine.POST("/api/account/validate/pin", handler.ValidatePin)
	// ok: scp.go.authz.route-without-auth-middleware
	engine.POST("/api/v1/login", handler.Login)
	// ok: scp.go.authz.route-without-auth-middleware
	engine.GET("/api/v1/quotes", handler.Quotes)
	// ok: scp.go.authz.route-without-auth-middleware
	engine.POST("/api/v1/portfolio", AuthMiddleware(authToken), handler.Portfolio)
}

func publicRoutes(app *fiber.App) {
	// ok: scp.go.authz.route-without-auth-middleware
	app.Post("/api/contact", handler.Contact)
	app.Get("/api/news", handler.News)
}
