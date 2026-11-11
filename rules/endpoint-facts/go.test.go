//go:build ignore

// Annotated tests for rules/endpoint-facts/go.yaml. The build tag keeps
// `go vet ./...` from compiling this file (it references undefined helpers on
// purpose: fact rules only need syntax, never types).
package facts

func routes(r *Router) {
	// ruleid: fact.go.route
	r.GET("/api/v1/orders", listOrders)

	// ruleid: fact.go.route, fact.go.route_middleware
	r.POST("/api/v1/orders", AuthMiddleware(), createOrder)

	// ruleid: fact.go.route, fact.go.route_middleware
	r.PUT("/api/v1/orders/:id", AuthMiddleware(), updateOrder)

	// ruleid: fact.go.route_handle
	r.Handle("GET", "/api/v1/reports", listReports)

	// ruleid: fact.go.route_handle, fact.go.route_handle_middleware
	r.Handle("POST", "/api/v1/reports", AuthMiddleware(), createReport)

	// ok: fact.go.route
	r.ServeStatic("/assets", staticHandler)
}
