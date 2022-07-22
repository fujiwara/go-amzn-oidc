package validator

import (
	"github.com/pkg/errors"
	"time"
)

type Claims map[string]interface{}

func (c *Claims) Valid() error {
	now := time.Now()
	exp := time.Unix(c.Exp(), 0)
	if !now.Before(exp) {
		return errors.New("token is expired")
	}
	return nil
}
