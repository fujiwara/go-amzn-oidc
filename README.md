# go-amzn-oidc

[![GoDoc](https://godoc.org/github.com/fujiwara/go-amzn-oidc/validator?status.svg)](https://godoc.org/github.com/fujiwara/go-amzn-oidc/validator)

## Description

go-amzn-oidc is a validator for x-amzn-oidc-data as JWT.

## Usage as a library

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

## With nginx auth_request

```console
$ amzn-oidc-validate-server
2020/10/24 01:50:06 [info] Listening 127.0.0.1:8080
```

nginx.conf
```conf
location = /oidc_validate {
	proxy_pass http://127.0.0.1:8080;
	proxy_set_header X-Amzn-OIDC-Data $http_x_amzn_oidc_data;
	proxy_set_header Content-Length "";
	proxy_pass_request_body off;
	internal;
}

location / {
	auth_request /oidc_validate;
	auth_request_set $email $upstream_http_x_auth_request_email;
	proxy_set_header X-Email $email;
	# ...
}
```

## LISENSE

MIT
