package validator

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"github.com/shogo82148/go-retry"
)

func init() {
	jwt.DecodePaddingAllowed = true
}

// RetryPolicy represents a policy for retrying http request to key URL.
var RetryPolicy = retry.Policy{
	MinDelay: 500 * time.Millisecond,
	MaxDelay: 3 * time.Second,
	MaxCount: 10,
}

var publicKeysCache = &sync.Map{}

var client = &http.Client{}

type keyURLGenerator func(*jwt.Token) (string, error)

// Validate validates x-amzn-oidc-data as JWT
func Validate(data string) (Claims, error) {
	return ValidateWithContext(context.Background(), data)
}

// ValidateWithContext validates x-amzn-oidc-data as JWT with context
func ValidateWithContext(ctx context.Context, data string) (Claims, error) {
	return validateWithKeyURLGenerator(ctx, data, publicKeyURL)
}

func validateWithKeyURLGenerator(ctx context.Context, data string, gen keyURLGenerator) (Claims, error) {
	claims := make(Claims, 0)
	_, err := jwt.ParseWithClaims(data, &claims, func(token *jwt.Token) (interface{}, error) {
		keyURL, err := gen(token)
		if err != nil {
			return nil, err
		}
		var publicKey *ecdsa.PublicKey
		err = RetryPolicy.Do(ctx, func() error {
			publicKey, err = fetchPublicKey(ctx, keyURL)
			return err
		})
		return publicKey, err
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func fetchPublicKey(ctx context.Context, keyURL string) (*ecdsa.PublicKey, error) {
	if key, ok := publicKeysCache.Load(keyURL); ok {
		return key.(*ecdsa.PublicKey), nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to new GET request for %s", keyURL)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get public key from %s", keyURL)
	}
	defer resp.Body.Close()
	pem, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get public key from %s", keyURL)
	}
	publicKey, err := jwt.ParseECPublicKeyFromPEM(pem)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse public key from %s", keyURL)
	}
	publicKeysCache.Store(keyURL, publicKey)

	return publicKey, nil
}

func headerString(token *jwt.Token, name string) (string, error) {
	_v, ok := token.Header[name]
	if !ok {
		return "", errors.Errorf("no %s in token header", name)
	}
	v, ok := _v.(string)
	if !ok {
		return "", errors.Errorf("no %s string in token header", name)
	}
	return v, nil
}

// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html#user-claims-encoding
func publicKeyURL(token *jwt.Token) (string, error) {
	arn, err := headerString(token, "signer")
	if err != nil {
		return "", err
	}
	kid, err := headerString(token, "kid")
	if err != nil {
		return "", err
	}
	if alg, _ := headerString(token, "alg"); alg != "ES256" {
		return "", errors.New("alg must be ES256")
	}

	parts := strings.Split(arn, ":")
	if len(parts) < 4 {
		return "", errors.Errorf("invalid arn format %s", arn)
	}
	partition, region := parts[1], parts[3]
	switch partition {
	case "aws":
		return fmt.Sprintf(
			"https://public-keys.auth.elb.%s.amazonaws.com/%s",
			region,
			kid,
		), nil
	case "aws-us-gov":
		return fmt.Sprintf(
			"https://s3-%s.amazonaws.com/aws-elb-public-keys-prod-%s/%s",
			region,
			region,
			kid,
		), nil
	}
	return "", errors.Errorf("unsupported arn partition %s", arn)
}
