package validator_test

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/fujiwara/go-amzn-oidc/validator"
)

func TestRealJWT(t *testing.T) {
	testJWT := "testdata/test.jwt"
	if _, err := os.Stat(testJWT); err != nil {
		t.Skipf("%s is not found", testJWT)
	}
	f, _ := os.Open(testJWT)
	b, _ := ioutil.ReadAll(f)
	f.Close()

	token := strings.TrimSpace(string(b))
	t.Log(token)
	c, err := validator.Validate(token)
	if err != nil {
		t.Error(err)
	}
	t.Log(c)
}
