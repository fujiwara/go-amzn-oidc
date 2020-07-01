# go-amzn-oidc

[![GoDoc](https://godoc.org/github.com/fujiwara/go-amzn-oidc/validator?status.svg)](https://godoc.org/github.com/fujiwara/go-amzn-oidc/validator)

## Description

go-amzn-oidc is a validator for x-amzn-oidc-data as JWT.

## Usage

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	validator "github.com/fujiwara/go-amzn-oidc/validator"
)

func handlerFunc(w http.ResponseWriter, r *http.Request) {
	claims, err := validator.Validate(r.Header.Get("x-amzn-oidc-data"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "validation error", err.Error())
		return
	}
	fmt.Fprintln(w, claims.Email())
}

func main() {
	http.HandleFunc("/", handlerFunc)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## LISENSE

MIT
