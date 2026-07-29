package main

import (
	"net/http"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/mongodb"
	"github.com/eadwinCode/better-auth-go/adapter/postgresql"
	"github.com/eadwinCode/better-auth-go/adapter/sqlite"
)

// compileServer exercises the public server shape from an external module. It
// is intentionally never executed: release certification only needs to prove
// that the tagged module and first-party adapter packages resolve and compile
// without a local replace directive.
func compileServer(config betterauth.Config) (http.Handler, error) {
	server, err := betterauth.New(config)
	if err != nil {
		return nil, err
	}
	return server.Handler(), nil
}

func main() {
	_ = mongodb.Config{}
	_, _ = postgresql.New(nil)
	_, _ = sqlite.New(nil)
	_, _ = compileServer(betterauth.Config{})
}
