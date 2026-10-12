package memory_test

import (
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
	"github.com/eadwinCode/better-auth-go/adaptertest"
)

func TestConformance(t *testing.T) {
	adaptertest.Run(t, func(*testing.T) betterauth.DatabaseAdapter {
		return memory.New()
	})
}

func schemaFactory(t *testing.T, schema betterauth.Schema) betterauth.DatabaseAdapter {
	t.Helper()
	configured, err := memory.New().WithSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	return configured
}

func TestAccountIdentity(t *testing.T) {
	adaptertest.RunAccountIdentity(t, schemaFactory)
}

func TestMappedIdentity(t *testing.T) {
	adaptertest.RunMappedIdentity(t, schemaFactory)
}
