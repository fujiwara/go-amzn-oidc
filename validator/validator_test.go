package validator_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fujiwara/go-amzn-oidc/validator"
	"github.com/golang-jwt/jwt/v4"
)

var privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
var publicKey = privateKey.PublicKey
var keyHandlerFunc = func(w http.ResponseWriter, r *http.Request) {
	b, _ := x509.MarshalPKIXPublicKey(&publicKey)
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}
	pem.Encode(w, block)
}

var keyURLTests = []struct {
	Token *jwt.Token
	URL   string
}{
	{
		Token: newToken(
			"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test/d74f8c34849f8790",
			"cca216b2-6fd4-4953-92d4-ec232ffb9891",
		),
		URL: "https://public-keys.auth.elb.us-east-1.amazonaws.com/cca216b2-6fd4-4953-92d4-ec232ffb9891",
	},
	{
		Token: newToken(
			"arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:loadbalancer/app/test/d74f8c34849f8790",
			"6db77464-4ac6-4968-9ec9-a6c669649ba1",
		),
		URL: "https://public-keys.auth.elb.ap-northeast-1.amazonaws.com/6db77464-4ac6-4968-9ec9-a6c669649ba1",
	},
	{
		Token: newToken(
			"arn:aws-us-gov:elasticloadbalancing:us-gov-east-1:123456789012:loadbalancer/app/test/d74f8c34849f8790",
			"d39846c3-18d4-4c5e-8148-27a63a4fa6d8",
		),
		URL: "https://s3-us-gov-east-1.amazonaws.com/aws-elb-public-keys-prod-us-gov-east-1/d39846c3-18d4-4c5e-8148-27a63a4fa6d8",
	},
}

func TestPublicKeyURL(t *testing.T) {
	for _, ts := range keyURLTests {
		t.Logf("token: %#v", ts.Token)
		if u, err := validator.PublicKeyURL(ts.Token); err != nil || u != ts.URL {
			t.Errorf("unexpected key url %s %v", u, err)
		}
	}
}

func TestValidate(t *testing.T) {
	sv := httptest.NewServer(http.HandlerFunc(keyHandlerFunc))
	defer sv.Close()
	gen := func(token *jwt.Token) (string, error) {
		return sv.URL, nil
	}
	ctx := context.Background()
	for _, ts := range keyURLTests {
		data, _ := ts.Token.SignedString(privateKey)
		t.Log("data", data)
		claims, err := validator.ValidateWithKeyURLGenerator(ctx, data, gen)
		if err != nil {
			t.Error("validate failed", err)
		}
		if claims.Valid() != nil {
			t.Error("token is not valid")
		}
		if claims.Email() != "foo@example.com" {
			t.Error("unexpected email", claims.Email())
		}
		if claims.UpdatedAt() != 1593592790 {
			t.Error("unexpected updated_at", claims.UpdatedAt())
		}
		if !claims.EmailVerified() {
			t.Error("unexpected email_verified", claims.EmailVerified())
		}
		t.Logf("validated %#v", claims)
	}
}

func newToken(arn, kid string) *jwt.Token {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"foo":            "bar",
		"email":          "foo@example.com",
		"updated_at":     1593592790,
		"email_verified": true,
	})
	token.Header["signer"] = arn
	token.Header["kid"] = kid
	token.Header["exp"] = time.Now().Unix() + 60
	return token
}
