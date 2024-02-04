package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"

	"github.com/codingconcepts/env"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/nicklaw5/helix/v2"

	"github.com/golden-vcr/auth/gen/queries"
	"github.com/golden-vcr/auth/internal/server"
	"github.com/golden-vcr/server-common/db"
	"github.com/golden-vcr/server-common/entry"
)

type Config struct {
	BindAddr   string `env:"BIND_ADDR"`
	ListenPort uint16 `env:"LISTEN_PORT" default:"5002"`

	TwitchChannelName  string `env:"TWITCH_CHANNEL_NAME" required:"true"`
	TwitchClientId     string `env:"TWITCH_CLIENT_ID" required:"true"`
	TwitchClientSecret string `env:"TWITCH_CLIENT_SECRET" required:"true"`

	SigningKeyId  string `env:"AUTH_SIGNING_KEY_ID" required:"true"`
	SigningKeyPem string `env:"AUTH_SIGNING_KEY_PEM" required:"true"`
	JwtIssuer     string `env:"AUTH_JWT_ISSUER" default:"https://goldenvcr.com/api/auth"`
	JwksJson      string `env:"AUTH_JWKS_JSON" required:"true"`
	SharedSecret  string `env:"AUTH_SHARED_SECRET" required:"true"`

	DatabaseHost     string `env:"PGHOST" required:"true"`
	DatabasePort     int    `env:"PGPORT" required:"true"`
	DatabaseName     string `env:"PGDATABASE" required:"true"`
	DatabaseUser     string `env:"PGUSER" required:"true"`
	DatabasePassword string `env:"PGPASSWORD" required:"true"`
	DatabaseSslMode  string `env:"PGSSLMODE"`
}

func main() {
	app := entry.NewApplication("auth")
	defer app.Stop()

	// Parse config from environment variables
	err := godotenv.Load()
	if err != nil && !os.IsNotExist(err) {
		app.Fail("Failed to load .env file", err)
	}
	config := Config{}
	if err := env.Set(&config); err != nil {
		app.Fail("Failed to load config", err)
	}

	// Parse the private key that we'll use to sign JWTs that we issue
	pemBlock, _ := pem.Decode([]byte(config.SigningKeyPem))
	if pemBlock == nil {
		app.Fail("Failed to decode signing key PEM from env", err)
	}
	signingKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		app.Fail("Failed to parse signing key from PEM block", err)
	}

	// Parse the JWKS JSON payload that we'll serve at /.well-known/jwks.json in order
	// to advertise the public key(s) that can be used to verify service tokens signed
	// by the auth service
	var jwksJson json.RawMessage
	if err := json.Unmarshal([]byte(config.JwksJson), &jwksJson); err != nil {
		app.Fail("Failed to parse JWKS JSON from env", err)
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
		app.Fail("Failed to open sql.DB", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		app.Fail("Failed to connect to database", err)
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
		app.Fail("Failed to get Twitch channel user ID", err)
	}

	// Initialize our HTTP server
	srv := server.New(channelUserId, config.TwitchClientId, config.TwitchClientSecret, config.SharedSecret, config.SigningKeyId, signingKey, config.JwtIssuer, jwksJson, q)
	r := mux.NewRouter()
	srv.RegisterRoutes(r)

	// Handle incoming HTTP connections until our top-level context is canceled, at
	// which point shut down cleanly
	entry.RunServer(app, r, config.BindAddr, int(config.ListenPort))
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
