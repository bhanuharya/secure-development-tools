package main

import "github.com/golang-jwt/jwt/v5"

const dbPassword = "S3cretPass!2024"

func sign(claims jwt.MapClaims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("my-jwt-signing-secret"))
}
