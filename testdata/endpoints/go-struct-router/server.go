package api

import "github.com/gofiber/fiber/v2"

// Server keeps the engine in a field and forwards Get/Post to it.
type Server struct {
	Router *fiber.App
}

func (s *Server) Run() {
	app := fiber.New()
	s.Router = app
	s.setupMiddlewares(app)

	api := app.Group("/api")
	s.secure(api)
	s.apiRoutes(api)

	NewAdmin(app).Register()
	s.routes(app)
}

func (s *Server) setupMiddlewares(app *fiber.App) {
	app.Use(requestLogger)
}

// secure registers the gate in a helper: routes on api after the call are protected.
func (s *Server) secure(r fiber.Router) {
	r.Use(requireToken)
}

func (s *Server) apiRoutes(r fiber.Router) {
	r.Get("/orders", listOrders)
}

func (s *Server) routes(app *fiber.App) {
	app.Get("/health", health)
	s.Post("/login", login)
	s.Post("/admin/purge", purge)
	s.Router.Get("/status", status)
}

func (s *Server) Post(path string, handlers ...fiber.Handler) {
	s.Router.Post(path, handlers...)
}

func (s *Server) Get(path string, handlers ...fiber.Handler) {
	s.Router.Get(path, handlers...)
}
