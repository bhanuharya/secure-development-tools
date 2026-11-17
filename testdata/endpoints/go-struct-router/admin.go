package api

import "github.com/gofiber/fiber/v2"

// Admin is built with its group in a composite literal.
type Admin struct {
	r fiber.Router
}

func NewAdmin(app *fiber.App) *Admin {
	return &Admin{r: app.Group("/staff", requireStaffRole)}
}

func (a *Admin) Register() {
	a.r.Delete("/users/:id", deleteUser)
}
