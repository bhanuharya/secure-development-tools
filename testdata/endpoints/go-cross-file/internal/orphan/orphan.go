package orphan

import "github.com/gofiber/fiber/v2"

// Register is not called anywhere in the service.
func Register(grp fiber.Router) {
	grp.Post("/payouts", payout)
}
