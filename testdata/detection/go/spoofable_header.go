package main

import "net/http"

func accountHandler(w http.ResponseWriter, r *http.Request) {
	uid := r.Header.Get("X-User-Id")
	w.Write([]byte(uid))
}
