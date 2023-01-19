package validator

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// NewHTTPHandlerFunc creates http handler func with timeout
func NewHTTPHandlerFunc(timeout time.Duration) func(w http.ResponseWriter, r *http.Request) {
	return newHTTPHandlerFuncWithKeyURLGenerator(publicKeyURL, timeout)
}

func newHTTPHandlerFuncWithKeyURLGenerator(gen func(token *jwt.Token) (string, error), timeout time.Duration) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		data := r.Header.Get("x-amzn-oidc-data")
		claims, err := validateWithKeyURLGenerator(ctx, data, gen)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			log.Printf("[error] validation failed. err:%s x-amzn-oidc-data:%s", err, data)
			fmt.Fprintln(w, "validation error", err.Error())
			return
		}
		log.Println("[debug] validated email", claims.Email())
		w.Header().Set("X-Auth-Request-Email", claims.Email())
		fmt.Fprintln(w, "OK")
	}
}
