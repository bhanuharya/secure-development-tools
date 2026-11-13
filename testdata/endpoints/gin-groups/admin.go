package main

import "github.com/gin-gonic/gin"

// registerReports is called nowhere in this service: the group it receives is
// not known, so its routes must stay unknown (SPEC §5).
func registerReports(r *gin.RouterGroup) {
	r.GET("/reports", listReports)
}
