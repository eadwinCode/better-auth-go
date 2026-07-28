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
