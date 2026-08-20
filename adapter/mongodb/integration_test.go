package mongodb_test

import (
	"context"
	"os"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/mongodb"
	"github.com/eadwinCode/better-auth-go/adaptertest"
	v17 "github.com/eadwinCode/better-auth-go/migration/v17"
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
	if err := adapter.EnsureIndexes(t.Context(), betterauth.CoreSchema()); err != nil {
		t.Fatal(err)
	}

	adaptertest.Run(t, func(t *testing.T) betterauth.DatabaseAdapter {
		return adapter
	})
}

func TestReleaseUpgradeFromEcf48ac(t *testing.T) {
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
	databaseName := "better_auth_go_upgrade_" + time.Now().UTC().Format("20060102150405_000000000")
	database := client.Database(databaseName)
	t.Cleanup(func() { _ = database.Drop(context.Background()) })
	adapter, err := mongodb.New(mongodb.Config{Database: database})
	if err != nil {
		t.Fatal(err)
	}
	legacyDatabase, err := betterauth.WrapDatabaseAdapter(adapter, adaptertest.LegacyCoreSchema())
	if err != nil {
		t.Fatal(err)
	}
	adaptertest.SeedReleaseBaseline(t, legacyDatabase)
	stagingDatabase, err := betterauth.WrapDatabaseAdapter(adapter, v17.StagingSchema())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v17.Backfill(t.Context(), stagingDatabase, v17.Options{}); err != nil {
		t.Fatalf("backfill account issuer: %v", err)
	}
	current := betterauth.CoreSchema()
	if err := adapter.EnsureIndexes(t.Context(), current); err != nil {
		t.Fatalf("upgrade current indexes: %v", err)
	}
	if err := adapter.EnsureIndexes(t.Context(), current); err != nil {
		t.Fatalf("idempotent current indexes: %v", err)
	}
	currentDatabase, err := betterauth.WrapDatabaseAdapter(adapter, current)
	if err != nil {
		t.Fatal(err)
	}
	adaptertest.AssertReleaseUpgrade(t, currentDatabase)
	for collection, expected := range map[string]string{
		betterauth.ModelSession: "user_sessions",
		betterauth.ModelAccount: "user_accounts",
	} {
		specifications, err := database.Collection(collection).Indexes().ListSpecifications(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		found := false
		names := make([]string, 0, len(specifications))
		for _, specification := range specifications {
			names = append(names, specification.Name)
			if specification.Name == expected {
				found = true
			}
		}
		if !found {
			t.Fatalf("current MongoDB index %q missing from %s: %v", expected, collection, names)
		}
	}
}
