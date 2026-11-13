package main

import "github.com/gofiber/fiber/v2"

func main() {
	app := fiber.New()
	app.Use("/admin", AuthMiddleware)
	app.Get("/admin/users", listUsers)
	app.Post("/transfer", transferFunds)
	app.Post("/protected", AuthMiddleware, createOrder)
}

func listUsers(c *fiber.Ctx) error      { return nil }
func transferFunds(c *fiber.Ctx) error  { return nil }
func createOrder(c *fiber.Ctx) error    { return nil }
func AuthMiddleware(c *fiber.Ctx) error { return nil }
