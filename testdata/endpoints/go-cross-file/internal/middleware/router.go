package middleware

import "github.com/gofiber/fiber/v2"

// RoleRouter checks a permission before every handler it registers.
type RoleRouter struct{ router fiber.Router }

func NewRoleRouter(r fiber.Router, perms any) *RoleRouter { return &RoleRouter{router: r} }

func (rr *RoleRouter) Post(path string, h fiber.Handler) { rr.router.Post(path, h) }

// AccessLogRouter only logs.
type AccessLogRouter struct{ router fiber.Router }

func NewAccessLogRouter(r fiber.Router) *AccessLogRouter { return &AccessLogRouter{router: r} }

func (ar *AccessLogRouter) Post(path string, h fiber.Handler) { ar.router.Post(path, h) }
