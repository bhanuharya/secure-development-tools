package main

import (
	"github.com/gofiber/fiber/v2"

	"example.com/shop/internal/middleware"
)

func routes(app *fiber.App) {
	app.Get("/health", health)

	admin := app.Group("/admin")
	checked := middleware.NewRoleRouter(admin, permissions)
	checked.Post("/refunds", refund)

	logged := middleware.NewAccessLogRouter(admin)
	logged.Post("/settings", updateSettings)
}
