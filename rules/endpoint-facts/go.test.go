//go:build ignore

// Annotated tests for rules/endpoint-facts/go.yaml. The build tag keeps
// `go vet ./...` from compiling this file (it references undefined helpers on
// purpose: fact rules only need syntax, never types).
package facts

func ginApp() {
	// ruleid: fact.go.engine
	r := gin.Default()

	// ruleid: fact.go.use1
	r.Use(Logger)

	// ruleid: fact.go.use2
	r.Use(Logger, Recoverer)

	// ruleid: fact.go.use3
	r.Use(Logger, Recoverer, Tracer)

	// ruleid: fact.go.group1
	api := r.Group("/api")

	// ruleid: fact.go.group2
	withAuth := r.Group("/api", AuthMiddleware())

	// ruleid: fact.go.group3
	withAuthAndLimit := r.Group("/api", AuthMiddleware(), RateLimit())

	// ruleid: fact.go.group4
	withAll := r.Group("/api", AuthMiddleware(), RateLimit(), Tracer())

	_ = withAuth
	_ = withAuthAndLimit
	_ = withAll

	// ruleid: fact.go.route1
	api.GET("/orders", listOrders)

	// ruleid: fact.go.route2
	api.POST("/orders", AuthMiddleware(), createOrder)

	// ruleid: fact.go.route3
	api.PUT("/orders", AuthMiddleware(), RateLimit(), updateOrder)

	// ruleid: fact.go.route4
	api.PATCH("/orders", AuthMiddleware(), RateLimit(), Tracer(), patchOrder)

	// ruleid: fact.go.route5
	api.DELETE("/orders", AuthMiddleware(), RateLimit(), Tracer(), Audit(), deleteOrder)

	// ruleid: fact.go.handle_verb1
	api.Handle("GET", "/reports", listReports)

	// ruleid: fact.go.handle_verb2
	api.Handle("GET", "/reports", AuthMiddleware(), listReports)

	// ruleid: fact.go.handle_verb3
	api.Handle("GET", "/reports", AuthMiddleware(), RateLimit(), listReports)
}

func libraryApp() {
	// ruleid: fact.go.engine
	app := fiber.New()

	// ruleid: fact.go.handle_path
	app.Handle("/orders", orders)

	// ruleid: fact.go.handlefunc_path
	mux.HandleFunc("/health", health)

	// ruleid: fact.go.chi_route
	app.Route("/files", func(r chi.Router) {
		// ruleid: fact.go.route1
		r.Get("/{id}", getFile)
	})

	// ruleid: fact.go.chi_group
	app.Group(func(r chi.Router) {
		// ruleid: fact.go.route1
		r.Get("/status", status)
	})
}
