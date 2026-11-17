package main

import "github.com/gofiber/fiber/v2"

func main() {
	app := fiber.New()
	app.Use(RequestLogger)
	api := app.Group("/api")
	api.Use(JwtMiddleware)
	api.Get("/orders", listOrders)
	admin := app.Group("/admin", RequireRole("admin"))
	admin.Delete("/users/:id", deleteUser)
	app.Get("/health", health)
}
