package main

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/codingconcepts/env"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/nicklaw5/helix/v2"
	"golang.org/x/sync/errgroup"

	"github.com/golden-vcr/auth/gen/queries"
	"github.com/golden-vcr/auth/internal/server"
	"github.com/golden-vcr/server-common/db"
)

type Config struct {
	BindAddr   string `env:"BIND_ADDR"`
	ListenPort uint16 `env:"LISTEN_PORT" default:"5002"`

	TwitchChannelName  string `env:"TWITCH_CHANNEL_NAME" required:"true"`
	TwitchClientId     string `env:"TWITCH_CLIENT_ID" required:"true"`
	TwitchClientSecret string `env:"TWITCH_CLIENT_SECRET" required:"true"`

	DatabaseHost     string `env:"PGHOST" required:"true"`
	DatabasePort     int    `env:"PGPORT" required:"true"`
	DatabaseName     string `env:"PGDATABASE" required:"true"`
	DatabaseUser     string `env:"PGUSER" required:"true"`
	DatabasePassword string `env:"PGPASSWORD" required:"true"`
	DatabaseSslMode  string `env:"PGSSLMODE"`

	SigningKeyId  string `env:"AUTH_SIGNING_KEY_ID" required:"true"`
	SigningKeyPem string `env:"AUTH_SIGNING_KEY_PEM" required:"true"`
	JwksJson      string `env:"AUTH_JWKS_JSON" required:"true"`
	SharedSecret  string `env:"AUTH_SHARED_SECRET" required:"true"`
}

func main() {
	// Parse config from environment variables
	err := godotenv.Load()
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("error loading .env file: %v", err)
	}
	config := Config{}
	if err := env.Set(&config); err != nil {
		log.Fatalf("error loading config: %v", err)
	}

	// Shut down cleanly on signal
	ctx, close := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGTERM)
	defer close()

	// Parse the private key that we'll use to sign JWTs that we issue
	pemBlock, _ := pem.Decode([]byte(config.SigningKeyPem))
	if pemBlock == nil {
		log.Fatalf("error decoding signing key PEM from env: %v", err)
	}
	signingKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		log.Fatalf("error parsing signing key from PEM block: %v", err)
	}

	// Configure our database connection and initialize a Queries struct, so we can read
	// and write to the 'auth' schema in response to HTTP requests
	connectionString := db.FormatConnectionString(
		config.DatabaseHost,
		config.DatabasePort,
		config.DatabaseName,
		config.DatabaseUser,
		config.DatabasePassword,
		config.DatabaseSslMode,
	)
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatalf("error opening database: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatalf("error connecting to database: %v", err)
	}
	q := queries.New(db)

	// Look up the user ID for our configured Twitch channel (i.e. goldenvcr), so we can
	// identify the broadcaster as a super-admin
	channelUserId, err := resolveTwitchChannelUserId(
		config.TwitchChannelName,
		config.TwitchClientId,
		config.TwitchClientSecret,
	)
	if err != nil {
		log.Fatalf("error getting Twitch channel user ID: %v", err)
	}

	// Initialize our HTTP server
	srv := server.New(channelUserId, config.TwitchClientId, config.TwitchClientSecret, config.SharedSecret, config.SigningKeyId, signingKey, q)
	r := mux.NewRouter()
	srv.RegisterRoutes(r)
	addr := fmt.Sprintf("%s:%d", config.BindAddr, config.ListenPort)
	server := &http.Server{Addr: addr, Handler: r}

	// Handle incoming HTTP connections until our top-level context is canceled, at
	// which point shut down cleanly
	fmt.Printf("Listening on %s...\n", addr)
	var wg errgroup.Group
	wg.Go(server.ListenAndServe)

	select {
	case <-ctx.Done():
		fmt.Printf("Received signal; closing server...\n")
		server.Shutdown(context.Background())
	}

	err = wg.Wait()
	if err == http.ErrServerClosed {
		fmt.Printf("Server closed.\n")
	} else {
		log.Fatalf("error running server: %v", err)
	}
}

func resolveTwitchChannelUserId(channelName string, clientId string, clientSecret string) (string, error) {
	client, err := newTwitchClientWithAppToken(clientId, clientSecret)
	if err != nil {
		return "", err
	}
	r, err := client.GetUsers(&helix.UsersParams{
		Logins: []string{channelName},
	})
	if err != nil {
		return "", fmt.Errorf("failed to get user ID: %w", err)
	}
	if r.StatusCode != 200 {
		return "", fmt.Errorf("got response %d from get users request: %s", r.StatusCode, r.ErrorMessage)
	}
	if len(r.Data.Users) != 1 {
		return "", fmt.Errorf("got %d results from get users request; expected exactly 1", len(r.Data.Users))
	}
	return r.Data.Users[0].ID, nil
}

func newTwitchClientWithAppToken(clientId string, clientSecret string) (*helix.Client, error) {
	c, err := helix.NewClient(&helix.Options{
		ClientID:     clientId,
		ClientSecret: clientSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Twitch API client: %w", err)
	}

	res, err := c.RequestAppAccessToken(nil)
	if err == nil && res.StatusCode != http.StatusOK {
		err = fmt.Errorf("got status %d: %s", res.StatusCode, res.ErrorMessage)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get app access token from Twitch API: %w", err)
	}

	c.SetAppAccessToken(res.Data.AccessToken)
	return c, nil
}
