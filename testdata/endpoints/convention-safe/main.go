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
	api.GET("/funds/rates", listRates)

	admin := api.Group("/admin", RequireRole("admin"))
	admin.DELETE("/sessions", revokeSession)
	admin.GET("/users", listUsers)
	admin.PUT("/roles/:id", updateRole)

	public := r.Group("/public")
	public.POST("/login", login)
	public.GET("/status", status)
}
