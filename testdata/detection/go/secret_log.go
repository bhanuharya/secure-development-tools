package main

import "log"

// The bearer token is written to the log.
func forward(bearerToken string) {
	log.Println("token: ", bearerToken)
}
