package server

import (
	"crypto/rsa"
	"encoding/json"

	"github.com/golden-vcr/server-common/hmac"
	"github.com/gorilla/mux"
)

type Server struct {
	channelUserId   string
	client          TwitchClient
	verifier        hmac.Verifier
	jwtSigningKeyId string
	jwtSigningKey   *rsa.PrivateKey
	jwksJson        json.RawMessage
	q               Queries
}

func New(channelUserId string, twitchClientId string, twitchClientSecret string, sharedSecret string, jwtSigningKeyId string, jwtSigningKey *rsa.PrivateKey, jwskJson json.RawMessage, q Queries) *Server {
	return &Server{
		channelUserId:   channelUserId,
		client:          NewTwitchClient(twitchClientId, twitchClientSecret),
		verifier:        hmac.NewVerifier(sharedSecret),
		jwtSigningKeyId: jwtSigningKeyId,
		jwtSigningKey:   jwtSigningKey,
		jwksJson:        jwskJson,
		q:               q,
	}
}

func (s *Server) RegisterRoutes(r *mux.Router) {
	// Authentication endpoints: allows the user to establish their identity by granting
	// our app a User Access Token via Twitch
	r.Path("/login").Methods("POST").HandlerFunc(s.handleLogin)
	r.Path("/refresh").Methods("POST").HandlerFunc(s.handleRefresh)
	r.Path("/logout").Methods("POST").HandlerFunc(s.handleLogout)

	// Service token endpoints: when another internal service needs authorization to
	// operate on a specific user's data (for example, in response to a Twitch webhook
	// or IRC chat event that positively identifies that user), that service can issue a
	// request to POST /service-token, signing the request using a shared HMAC secret to
	// verify that it's a legitimately authorized service: in response, the auth service
	// will issue a short-lived JWT that authorizes the bearer to modify the target user
	// (as identified in the JWT claims) with viewer-level access. APIs that require
	// authorization can then accept that JWT in place of a Twitch User Access Token,
	// verifying the JWT using the public key advertised via jwks.json to authorize the
	// request.
	r.Path("/service-token").Methods("POST").HandlerFunc(s.handlePostServiceToken)
	r.Path("/.well-known/jwks.json").Methods("GET").HandlerFunc(s.handleGetJWKS)

	// Access endpoints: allows other APIs to determine whether the user identified by a
	// User Access Token (supplied in the Authorization header) should be authorized to
	// use the app
	r.Path("/access").Methods("GET").HandlerFunc(s.handleGetAccess)
}
