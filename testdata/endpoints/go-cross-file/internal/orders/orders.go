package orders

import "github.com/gofiber/fiber/v2"

func Register(grp fiber.Router) {
	g := grp.Group("/orders")
	g.Get("/", list)
	g.Post("/:id/cancel", cancel)
}
