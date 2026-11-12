package main

import "github.com/gin-gonic/gin"

func setup() {
	r := gin.New()
	r.POST("/transfer",
		// AuthMiddleware(),
		Logger(),
		handle)
}

func Logger() gin.HandlerFunc         { return nil }
func handle(c *gin.Context)           {}
func AuthMiddleware() gin.HandlerFunc { return nil }
