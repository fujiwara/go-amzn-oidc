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

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/shogo82148/go-retry"
)

var retryPolicy = retry.Policy{
	MinDelay: 500 * time.Millisecond,
	MaxDelay: 3 * time.Second,
	MaxCount: 10,
}

var publicKeysCache = &sync.Map{}

var client = &http.Client{}

type keyURLGenerator func(*jwt.Token) (string, error)

// Validate validates x-amzn-oidc-data as JWT
func Validate(data string) (*jwt.Token, error) {
	return ValidateWithContext(context.Background(), data)
}

// ValidateWithContext validates x-amzn-oidc-data as JWT with context
func ValidateWithContext(ctx context.Context, data string) (*jwt.Token, error) {
	return validateWithKeyURLGenerator(ctx, data, publicKeyURL)
}

func validateWithKeyURLGenerator(ctx context.Context, data string, gen keyURLGenerator) (*jwt.Token, error) {
	return jwt.Parse(data, func(token *jwt.Token) (interface{}, error) {
		keyURL, err := gen(token)
		if err != nil {
			return nil, err
		}
		var publicKey *ecdsa.PublicKey
		err = retryPolicy.Do(ctx, func() error {
			publicKey, err = fetchPublicKey(ctx, keyURL)
			return err
		})
		return publicKey, err
	})
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

// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html#user-claims-encoding
func publicKeyURL(token *jwt.Token) (string, error) {
	_arn, ok := token.Header["signer"]
	if !ok {
		return "", errors.New("no signer in token header")
	}
	arn, ok := _arn.(string)
	if !ok {
		return "", errors.New("no signer string in token header")
	}

	_kid, ok := token.Header["kid"]
	if !ok {
		return "", errors.New("no kid in token header")
	}
	kid, ok := _kid.(string)
	if !ok {
		return "", errors.New("no signer string in token header")
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
