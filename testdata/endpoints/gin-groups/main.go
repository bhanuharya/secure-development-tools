package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.New()
	r.Use(Logger())
	api := r.Group("/api", AuthMiddleware())
	api.GET("/orders", listOrders)
	admin := api.Group("/admin", RequireRole("admin"))
	admin.DELETE("/orders/:id", deleteOrder)
	registerUsers(admin)
	public := r.Group("/public")
	public.GET("/status", status)
}

func registerUsers(g *gin.RouterGroup) {
	g.POST("/users", createUser)
}
