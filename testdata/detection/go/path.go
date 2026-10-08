package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, _ := os.ReadFile(filepath.Join("/data/reports", name))
	w.Write(data)
}
