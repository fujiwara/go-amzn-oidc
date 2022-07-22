package main

//go:generate go run genclaims.go -output ../claims_gen.go
//go:generate gofmt -w ../claims_gen.go

import (
	"flag"
	"fmt"
	"os"
	"text/template"

	"github.com/serenize/snaker"
)

// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
var claimFields = map[string][]string{
	"string": {
		"sub",
		"name",
		"given_name",
		"family_name",
		"middle_name",
		"nickname",
		"preferred_username",
		"profile",
		"picture",
		"website",
		"email",
		"gender",
		"birthdate",
		"zoneinfo",
		"locale",
		"phone_number",
	},
	"float64": {
		"updated_at",
	},
	"bool": {
		"email_verified",
		"phone_number_verified",
	},
	"int64": {
		"exp",
	},
}

var zeroValues = map[string]string{
	"string":  `""`,
	"float64": `0`,
	"bool":    `false`,
	"int64":   `0`,
}

var tmplSrc = `
func (c Claims) {{.NameCamel}}() {{.Type}} {
	_value, ok := c["{{.Name}}"]
	if !ok {
		return {{.ZeroValue}}
	}
	value, ok := _value.({{.Type}})
	if !ok {
		return {{.ZeroValue}}
	}
	return value
}
`

var tmpl = template.Must(template.New("claims").Parse(tmplSrc))

func main() {
	var path string
	flag.StringVar(&path, "output", "", "output file path")
	flag.Parse()
	if path == "" {
		panic("no -output")
	}

	os.Truncate(path, 0)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fmt.Fprintln(f, `package validator`)
	fmt.Fprintln(f, `// Code generated by genclaims.go; DO NOT EDIT.`)
	for _, typeName := range []string{"string", "bool", "float64", "int64"} {
		for _, name := range claimFields[typeName] {
			err := tmpl.Execute(f,
				struct {
					Type      string
					Name      string
					NameCamel string
					ZeroValue string
				}{
					Type:      typeName,
					Name:      name,
					NameCamel: snaker.SnakeToCamel(name),
					ZeroValue: zeroValues[typeName],
				})
			if err != nil {
				panic(err)
			}
		}
	}
}
