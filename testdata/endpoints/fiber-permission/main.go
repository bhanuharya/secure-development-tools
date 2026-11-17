package main

import "github.com/gofiber/fiber/v2"

type permissionConfig struct {
	PermissionTransfer string
}

var config = permissionConfig{PermissionTransfer: "transfers.write"}

func main() {
	app := fiber.New()
	app.Post("/transfers", RequirePermission(config.PermissionTransfer), transferFunds)
}

func transferFunds(c *fiber.Ctx) error { return nil }

func RequirePermission(permission string) fiber.Handler {
	return func(c *fiber.Ctx) error { return c.Next() }
}
