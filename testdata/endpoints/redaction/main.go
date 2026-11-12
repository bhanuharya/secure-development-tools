package main
func main() {
 app := fiber.New()
 app.Use(basicauth.New(basicauth.Config{
  Users: map[string]string{
   "operator": "synthetic_Fiber7Demo!",
  },
 }))
 app.Post("/transfer", handle)
 r := gin.New()
 r.Use(gin.BasicAuth(gin.Accounts{
  "operator": "synthetic_Only7Demo!",
  "reader": "synthetic_Other8Demo!",
  "writer": "synthetic_Third9Demo!",
  "auditor": "synthetic_Four0Demo!",
  "guest": "synthetic_Fifth1Demo!",
 }))
 r.POST("/transfer", handle)
 r.POST("/admin/roles", RequireRole("admin"), handle)
}
