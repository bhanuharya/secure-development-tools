package main

import (
	"crypto/md5"
	"fmt"
	"math/rand"
)

func hashPassword(password string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(password)))
}

func sessionToken() string {
	return fmt.Sprintf("%d", rand.Int63())
}
