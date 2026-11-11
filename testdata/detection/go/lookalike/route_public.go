package main

import "github.com/gin-gonic/gin"

// Login and a read-only quote list are public by design; the write route is protected.
func routes(engine *gin.Engine, authToken string) {
	engine.POST("/api/v1/login", handler.Login)
	engine.GET("/api/v1/quotes", handler.Quotes)
	engine.POST("/api/v1/orders", AuthMiddleware(authToken), handler.CreateOrder)
}
