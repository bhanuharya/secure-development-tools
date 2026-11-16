package response

import "github.com/gofiber/fiber/v2"

// Success reads the language header with a variable default: c is a request,
// not a router, whatever its second argument is.
func Success(c *fiber.Ctx, data interface{}, fallback string) error {
	lang := c.Get("Accept-Language", fallback)
	return c.JSON(fiber.Map{"lang": lang, "data": data})
}
