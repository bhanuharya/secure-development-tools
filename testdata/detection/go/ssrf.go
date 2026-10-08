package main

import (
	"io"
	"net/http"
)

func fetch(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(r.URL.Query().Get("url"))
	if err == nil {
		io.Copy(w, resp.Body)
	}
}
