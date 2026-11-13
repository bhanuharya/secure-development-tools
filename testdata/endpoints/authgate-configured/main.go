package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.New()
	api := r.Group("/api", checkCaller())
	api.POST("/orders", createOrder)
	api.GET("/orders", listOrders)
}
