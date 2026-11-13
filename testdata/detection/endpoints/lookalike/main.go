package main

import "github.com/gin-gonic/gin"

// Login and health are public by design; every state-changing route is behind
// the same authentication middleware.
func main() {
	r := gin.New()
	r.POST("/auth/login", login)
	r.GET("/health", health)

	api := r.Group("/api", AuthMiddleware())
	api.POST("/orders", createOrder)
	api.PUT("/orders/:id", updateOrder)
	api.PATCH("/orders/:id", patchOrder)
	api.DELETE("/orders/:id", deleteOrder)
	api.POST("/accounts", createAccount)
}
