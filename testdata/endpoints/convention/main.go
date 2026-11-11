package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.New()
	r.Use(Logger())

	api := r.Group("/api", AuthMiddleware())
	api.POST("/orders", createOrder)
	api.PUT("/orders/:id", updateOrder)
	api.PATCH("/orders/:id", patchOrder)
	api.DELETE("/orders/:id", deleteOrder)
	api.POST("/accounts", createAccount)
	api.POST("/funds/deposits", depositFunds)
	api.POST("/notifications", sendNotification)

	admin := api.Group("/admin", RequireRole("admin"))
	admin.DELETE("/sessions", revokeSession)

	r.POST("/api/funds/transfer", transferFunds)
	r.POST("/api/v1/login", login)
	r.GET("/api/admin/users", listUsers)
	r.PUT("/api/admin/roles/:id", AuthMiddleware(), updateRole)
}
