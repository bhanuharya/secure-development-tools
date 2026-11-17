package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.New()
	r.Use(gin.Logger())
	api := r.Group("/api", gin.BasicAuth(gin.Accounts{"operator": "S3cretValue42"}))
	api.POST("/one", handle)
	api.POST("/two", handle)
	api.POST("/three", handle)
	api.POST("/four", handle)
	r.POST("/records", handle)
}

func handle(c *gin.Context) {}
