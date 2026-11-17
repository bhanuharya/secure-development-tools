package main

import "github.com/gin-gonic/gin"

func protectedServer() *gin.Engine {
	r := gin.New()
	r.Use(AuthMiddleware())
	r.POST("/orders", createOrder)
	return r
}

func publicServer() *gin.Engine {
	r := gin.New()
	r.POST("/transfer", transferFunds)
	return r
}

func createOrder(c *gin.Context)   {}
func transferFunds(c *gin.Context) {}

func AuthMiddleware() gin.HandlerFunc { return nil }
