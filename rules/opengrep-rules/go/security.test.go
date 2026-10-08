package security_test

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// Annotated tests for go/security.yaml.
func tainted(arg string) {
	// ruleid: scp.go.injection.command
	exec.Command("sh", "-c", arg)
}

func safe(arg string) {
	// ok: scp.go.injection.command
	exec.Command("echo", arg)
}

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	// ruleid: scp.go.path-traversal.request-controlled-path
	data, _ := os.ReadFile(filepath.Join("/data/reports", name))
	w.Write(data)
}

func downloadByName(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("file"))
	// ok: scp.go.path-traversal.request-controlled-path
	data, _ := os.ReadFile(filepath.Join("/data/reports", name))
	w.Write(data)
}

func fixedFile(w http.ResponseWriter, r *http.Request) {
	// ok: scp.go.path-traversal.request-controlled-path
	data, _ := os.ReadFile("/data/reports/latest.csv")
	w.Write(data)
}
