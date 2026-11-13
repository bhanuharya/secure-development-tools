package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.New()
	r.GET("/health", health)
	r.POST("/api/transfer", transfer)
	r.GET("/api/orders", listOrders)
	r.POST("/admin/roles", RequireRole("admin"), updateRoles)
	r.Run()
}
