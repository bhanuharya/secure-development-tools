package main

import (
	"github.com/gofiber/fiber/v2"

	"example.com/shop/internal/auth"
	"example.com/shop/internal/catalog"
	"example.com/shop/internal/handler"
	"example.com/shop/internal/orders"
	"example.com/shop/internal/reporting"
)

func main() {
	app := fiber.New()
	app.Use(requestLogger)

	api := app.Group("/api")
	jwt := auth.RequireToken(publicKey)
	api.Use(jwt)
	orders.Register(api)
	reports.Register(api)

	h := handler.New()
	h.Routes(api)

	// The same reports package, registered a second time for staff.
	staff := app.Group("/staff", auth.RequireStaffToken())
	reports.Register(staff)

	catalog.Register(app.Group("/public"))

	serve(app)
}
