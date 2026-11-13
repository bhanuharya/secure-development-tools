package main

import "github.com/gofiber/fiber/v2"

func serve(app *fiber.App) {
	routes(app)
	_ = app.Listen(":8080")
}
