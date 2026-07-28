package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/mongodb"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type applicationMailer struct{}

func (applicationMailer) Send(_ context.Context, message betterauth.Mail) error {
	// Replace with a transactional provider. This intentionally does not log the
	// token or action URL.
	log.Printf("deliver auth mail kind=%s to=%s", message.Kind, message.To)
	return nil
}

type applicationAuthorization struct{}

func (applicationAuthorization) CanImpersonate(context.Context, betterauth.User, betterauth.User) error {
	return errors.New("example denies impersonation; connect your authorization policy")
}

func main() {
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		log.Fatal("MONGODB_URI is required")
	}
	publicURL := envOr("AUTH_PUBLIC_URL", "http://localhost:8080")
	appOrigin := envOr("APP_ORIGIN", "http://localhost:3000")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	database, err := mongodb.New(mongodb.Config{Database: client.Database("better_auth_example")})
	if err != nil {
		log.Fatal(err)
	}
	auth, err := betterauth.New(betterauth.Config{
		PublicURL:               publicURL,
		TrustedOrigins:          []string{appOrigin},
		Database:                database,
		Mailer:                  applicationMailer{},
		ImpersonationAuthorizer: applicationAuthorization{},
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := database.EnsureIndexes(ctx, auth.Schema()); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
