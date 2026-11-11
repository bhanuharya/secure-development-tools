package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()

	r.GET("/api/v1/orders", AuthMiddleware(), listOrders)
	r.POST("/api/v1/orders", AuthMiddleware(), createOrder)
	r.PUT("/api/v1/orders/:id", AuthMiddleware(), updateOrder)
	r.GET("/api/v1/health", health)
	r.DELETE("/api/v1/orders/:id", deleteOrder)
	r.POST("/api/v1/login", login)
}

func AuthMiddleware() gin.HandlerFunc { return nil }
func listOrders(c *gin.Context)       {}
func createOrder(c *gin.Context)      {}
func updateOrder(c *gin.Context)      {}
func health(c *gin.Context)           {}
func deleteOrder(c *gin.Context)      {}
func login(c *gin.Context)            {}
