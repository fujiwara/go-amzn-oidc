package validator

import "github.com/golang-jwt/jwt/v5"

type Claims map[string]any

var _ jwt.Claims = Claims{}

// Valid is kept for backward compatibility. It always returns nil.
func (c Claims) Valid() error {
	return nil
}

func (c Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.MapClaims(c).GetExpirationTime()
}

func (c Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.MapClaims(c).GetIssuedAt()
}

func (c Claims) GetNotBefore() (*jwt.NumericDate, error) {
	return jwt.MapClaims(c).GetNotBefore()
}

func (c Claims) GetIssuer() (string, error) {
	return jwt.MapClaims(c).GetIssuer()
}

func (c Claims) GetSubject() (string, error) {
	return jwt.MapClaims(c).GetSubject()
}

func (c Claims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.MapClaims(c).GetAudience()
}
