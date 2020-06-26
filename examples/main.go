package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	validator "github.com/fujiwara/go-amzn-oidc/validator"
)

func handlerFunc(w http.ResponseWriter, r *http.Request) {
	token, err := validator.Validate(r.Header.Get("x-amzn-oidc-data"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "validation error", err.Error())
		return
	}
	email := token.Claims.(jwt.MapClaims)["email"]
	fmt.Fprintln(w, email)
}

func main() {
	http.HandleFunc("/", handlerFunc)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
