package main

import "github.com/labstack/echo/v4"

func main() {
	e := echo.New()
	e.Use(RequestLogger)
	api := e.Group("/api", JwtMiddleware())
	api.GET("/orders", listOrders)
	api.POST("/orders", createOrder, RateLimit())
	admin := api.Group("/admin", RequireRole("admin"))
	admin.DELETE("/users/:id", deleteUser)
	e.GET("/health", health)
}
