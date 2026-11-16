package main

import (
	"github.com/gofiber/fiber/v2"

	"example.com/shapes/internal/general"
	"example.com/shapes/internal/response"
)

func requireToken(c *fiber.Ctx) error { return c.Next() }

func main() {
	app := fiber.New(fiber.Config{
		// The error handler reads a header: c.Get(key, default) is not a route.
		ErrorHandler: func(ctx *fiber.Ctx, err error) error {
			lang := ctx.Get("Accept-Language", "en")
			return ctx.SendString(lang)
		},
	})

	// fiber adds the missing leading slash: these serve /health and /api/...
	app.Get("health", health)

	api := app.Group("api", requireToken)
	api.Get("orders", listOrders)
	general.Register(api.Group("general"))

	app.Listen(":8080")
}

func health(c *fiber.Ctx) error { return response.Success(c, "ok", "en") }

func listOrders(c *fiber.Ctx) error { return response.Success(c, nil, "en") }
