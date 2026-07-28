package mongodb_test

import (
	"context"
	"os"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/mongodb"
	"github.com/eadwinCode/better-auth-go/adaptertest"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestConformance(t *testing.T) {
	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		t.Skip("MONGODB_URI is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	databaseName := "better_auth_go_test_" + time.Now().UTC().Format("20060102150405")
	t.Cleanup(func() { _ = client.Database(databaseName).Drop(context.Background()) })
	adapter, err := mongodb.New(mongodb.Config{Database: client.Database(databaseName)})
	if err != nil {
		t.Fatal(err)
	}

	adaptertest.Run(t, func(t *testing.T) betterauth.DatabaseAdapter {
		return adapter
	})
}
