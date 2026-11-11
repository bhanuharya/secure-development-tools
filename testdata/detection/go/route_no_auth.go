package main

import "github.com/gin-gonic/gin"

// The transfer route has no auth middleware while its neighbour has one.
func routes(engine *gin.Engine, authToken string) {
	engine.POST("/api/v1/orders", AuthMiddleware(authToken), handler.CreateOrder)
	engine.POST("/api/funds/transfer", handler.Transfer)
}
