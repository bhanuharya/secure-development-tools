package main

import (
	"bcrypt"
	"log"
)

// An error value whose name mentions a token, and a one-way password check.
func refresh(errToken error, user User, password string) error {
	log.Printf("refresh failed: %v", errToken)
	return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
}
