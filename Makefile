.PHONY: build test clean release

build:
	cd cmd/amzn-oidc-validate-server && go build .

test:
	go clean -testcache
	go test -v -race ./...

clean:
	rm -fr cmd/amzn-oidc-validate-server/amzn-oidc-validate-server dist/*

release:
	goreleaser build --snapshot --rm-dist
