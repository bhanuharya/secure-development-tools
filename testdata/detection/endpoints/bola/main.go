package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.New()
	api := r.Group("/api", AuthMiddleware())
	api.GET("/orders/:orderId", getOrder)
	api.GET("/profiles/:profileId", getProfile)
}

func getOrder(c *gin.Context) {
	var order Order
	db.First(&order, c.Param("orderId"))
	c.JSON(200, order)
}

func getProfile(c *gin.Context) {
	uid := c.Get("userID")
	var prof Profile
	db.Where("id = ? AND user_id = ?", c.Param("profileId"), uid).First(&prof)
	c.JSON(200, prof)
}
