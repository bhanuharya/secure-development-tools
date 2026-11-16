package general

import "github.com/gofiber/fiber/v2"

func Register(grp fiber.Router) {
	grp.Get("ping", ping)
	grp.Get("", index)
}

func ping(c *fiber.Ctx) error  { return c.SendString("pong") }
func index(c *fiber.Ctx) error { return c.SendString("general") }
