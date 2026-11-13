package catalog

import "github.com/gofiber/fiber/v2"

func Register(grp fiber.Router) {
	grp.Get("/products", listProducts)
	grp.Post("/admin/import", importProducts)
}
