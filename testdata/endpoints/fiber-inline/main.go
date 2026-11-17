package main

import "github.com/gofiber/fiber/v2"

func main() {
	app := fiber.New()
	app.Post("/transfer", AuthMiddleware, transferFunds)
}

func transferFunds(c *fiber.Ctx) error  { return nil }
func AuthMiddleware(c *fiber.Ctx) error { return nil }
