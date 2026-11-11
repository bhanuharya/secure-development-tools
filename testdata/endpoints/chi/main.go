package main

import "github.com/go-chi/chi/v5"

func main() {
	r := chi.NewRouter()
	r.Use(RequestLogger)
	r.Route("/api", func(r chi.Router) {
		r.With(JwtMiddleware).Get("/orders", listOrders)
		r.Post("/orders", createOrder)
	})
	r.Route("/admin", func(r chi.Router) {
		r.Use(AdminOnly)
		r.Delete("/users/{id}", deleteUser)
	})
	r.Get("/health", health)
}
