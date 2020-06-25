package validator

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

var publicKeysCache = &sync.Map{}

type keyURLGenerator func(*jwt.Token) (string, error)

// Validate validates x-amzn-oidc-data as JWT
func Validate(data string) (*jwt.Token, error) {
	return validateWithKeyURLGenerator(data, publicKeyURL)
}

func validateWithKeyURLGenerator(data string, gen keyURLGenerator) (*jwt.Token, error) {
	return jwt.Parse(data, func(token *jwt.Token) (interface{}, error) {
		keyURL, err := gen(token)
		if err != nil {
			return nil, err
		}
		return fetchPublicKey(keyURL)
	})
}

func fetchPublicKey(keyURL string) (*ecdsa.PublicKey, error) {
	if key, ok := publicKeysCache.Load(keyURL); ok {
		return key.(*ecdsa.PublicKey), nil
	}

	resp, err := http.Get(keyURL)
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
