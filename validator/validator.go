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

// Validate validates x-amzn-oidc-data JWT string
func Validate(data string) (*jwt.Token, error) {
	return jwt.Parse(data, fetchPublicKey)
}

func fetchPublicKey(token *jwt.Token) (interface{}, error) {
	keyURL, err := publicKeyURL(token)
	if err != nil {
		return nil, err
	}
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

func arnToRegion(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 4 {
		return ""
	}
	return parts[3]
}

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

	region := arnToRegion(arn)
	if region == "" {
		return "", errors.Errorf("no region found in singer %s", arn)
	}
	return fmt.Sprintf("https://public-keys.auth.elb.%s.amazonaws.com/%s", region, kid), nil
}
