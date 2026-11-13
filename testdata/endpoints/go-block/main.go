package main

import "github.com/gin-gonic/gin"

func setup() {
	r := gin.New()
	{
		r := gin.New()
		r.Use(AuthMiddleware())
		r.POST("/private", handle)
	}
	r.POST("/transfer", handle)
}

func AuthMiddleware() gin.HandlerFunc { return nil }
func handle(c *gin.Context)           {}
