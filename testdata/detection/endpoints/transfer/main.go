package main

import "github.com/gin-gonic/gin"

// Every state-changing route sits behind the auth group except the money
// transfer, which is registered on the engine itself.
func main() {
	r := gin.New()
	api := r.Group("/api", AuthMiddleware())

	api.POST("/accounts", createAccount)
	api.PUT("/accounts/:id", updateAccount)
	api.PATCH("/orders/:id", patchOrder)
	api.DELETE("/orders/:id", deleteOrder)
	api.POST("/orders", createOrder)

	// A sibling with the middleware inline is the evidence the rule pack uses
	// to show this router protects routes one by one.
	r.GET("/api/v1/profile", AuthMiddleware(), getProfile)

	r.POST("/api/funds/transfer", transferFunds)
}
