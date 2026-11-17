package auth

import "github.com/gofiber/fiber/v2"

func RequireToken(key string) fiber.Handler { return nil }

func RequireStaffToken() fiber.Handler { return nil }
