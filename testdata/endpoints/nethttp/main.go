package main

import "net/http"

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", health)
	mux.Handle("/orders", authWrap(listOrders))
	mux.HandleFunc("/public", status)
	http.HandleFunc("/metrics", metrics)
}
