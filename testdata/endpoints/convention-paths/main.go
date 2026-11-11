package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.New()
	api := r.Group("/api", AuthMiddleware())
	api.POST("/orders", createOrder)
	api.PUT("/orders/:id", updateOrder)
	api.PATCH("/orders/:id", patchOrder)
	api.DELETE("/orders/:id", deleteOrder)
	api.POST("/accounts", createAccount)
	api.POST("/account/change-password", changePassword)
	api.POST("/users/:id/change-password", changePasswordForUser)

	admin := api.Group("/admin", RequireRole("admin"))
	admin.PUT("/roles/:id", updateRole)

	r.POST("/api/v1/registration", register)
	r.POST("/api/v2/registration", registerV2)
	r.POST("/registration/validate-account", validateAccount)

	r.POST("/api/v1/auth/reset-password", resetPassword)
	r.POST("/api/reports", buildReport)
}
