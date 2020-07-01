package validator

type Claims map[string]interface{}

func (c *Claims) Valid() error {
	return nil
}
