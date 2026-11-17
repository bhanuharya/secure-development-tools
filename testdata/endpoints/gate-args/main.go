package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.New()
	r.Use(cors.New(cors.Config{AllowOrigins: []string{"*"}, AllowHeaders: []string{"Authorization"}}))
	r.POST("/transfer", transferFunds)
}

func transferFunds(c *gin.Context) {}
