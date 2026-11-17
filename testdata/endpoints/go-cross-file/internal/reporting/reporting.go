// Package reports lives in internal/reporting: callers import it by path and
// refer to it by its package name.
package reports

import "github.com/gofiber/fiber/v2"

func Register(grp fiber.Router) {
	grp.Get("/reports/export", export)
}
