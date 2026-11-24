package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.New()
	api := r.Group("/api", AuthMiddleware())
	api.GET("/orders/:orderId", getOwnOrder)
}

func getOwnOrder(c *gin.Context) {
	uid := c.Get("userID")
	var order Order
	db.Where("id = ? AND user_id = ?", c.Param("orderId"), uid).First(&order)
	c.JSON(200, order)
}
