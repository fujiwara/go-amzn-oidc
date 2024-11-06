package validator

import (
	"github.com/pkg/errors"
	"math"
	"time"
)

type Claims map[string]interface{}

func (c *Claims) Valid() error {
	now := time.Now()
	exp := timeFromFloatSeconds(c.Exp())
	if !now.Before(exp) {
		return errors.New("token is expired")
	}
	return nil
}

func timeFromFloatSeconds(f float64) time.Time {
	integ, decim := math.Modf(f)
	return time.Unix(int64(integ), int64(decim*(1e9)))
}
