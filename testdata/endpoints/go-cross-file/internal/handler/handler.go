package handler

import "github.com/gofiber/fiber/v2"

type Handler struct{}

func New() *Handler { return &Handler{} }

func (h *Handler) Routes(r fiber.Router) {
	r.Delete("/users/:id", h.deleteUser)
}
