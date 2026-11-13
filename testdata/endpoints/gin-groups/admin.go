package main

import "github.com/gin-gonic/gin"

// registerReports is called from another file: the group it receives is not
// visible here, so its routes must stay unknown (SPEC §5).
func registerReports(r *gin.RouterGroup) {
	r.GET("/reports", listReports)
}
