package validator_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/fujiwara/go-amzn-oidc/validator"
)

func TestHTTPHandlerFunc(t *testing.T) {
	keySv := httptest.NewServer(http.HandlerFunc(keyHandlerFunc))
	defer keySv.Close()
	gen := func(token *jwt.Token) (string, error) {
		return keySv.URL, nil
	}
	hf := validator.NewHTTPHandlerFuncWithKeyURLGenerator(gen, time.Second)
	validatorSv := httptest.NewServer(http.HandlerFunc(hf))
	defer validatorSv.Close()

	for _, ts := range keyURLTests {
		data, _ := ts.Token.SignedString(privateKey)

		// OK
		resp, err := requestHTTPHandlerFunc(validatorSv.URL, data)
		if err != nil {
			t.Error(err)
			continue
		}
		email := resp.Header.Get("x-auth-request-email")
		if email != "foo@example.com" {
			t.Error("unexpected email", email)
		}

		// NG
		corrupt := data[0 : len(data)-10] // invalid signature
		resp, err = requestHTTPHandlerFunc(validatorSv.URL, corrupt)
		if err != nil {
			t.Error(err)
			continue
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("must be forbidden got status %s", resp.Status)
		}
		if email := resp.Header.Get("x-auth-request-email"); email != "" {
			t.Errorf("x-auth-request-email must be empty got %s", email)
		}
	}
}

func requestHTTPHandlerFunc(u, data string) (*http.Response, error) {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Add("X-Amzn-OIDC-Data", data)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return resp, nil
}
