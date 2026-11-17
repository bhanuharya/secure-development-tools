package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.New()
	r.POST("/accounts/transfer", logger1, logger2, logger3, logger4, logger5, handle)
}

func logger1(c *gin.Context) {}
func logger2(c *gin.Context) {}
func logger3(c *gin.Context) {}
func logger4(c *gin.Context) {}
func logger5(c *gin.Context) {}
func handle(c *gin.Context)  {}
