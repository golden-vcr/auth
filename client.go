package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrUnauthorized indicates that the request failed due to invalid credentials: if this
// is the first failed request, the caller may initiate a refresh to get a new access
// token, then try again
var ErrUnauthorized = errors.New("access token was not accepted")

// contextKeyClaims is the key under which our HTTP middleware will stash a valid
// *auth.AccessClaims value once authorization succeeds
var contextKeyClaims = "gvcr-claims"

// Client represents an HTTP client that can call the auth server's GET /access endpoint
// in order to verify a user's level of access
type Client interface {
	// CheckAccess uses the provided Twitch User Access token to identify the user and
	// ascertain what role they have been granted for access control: if error is
	// non-nil, the access token is valid and the user's identity is verified
	CheckAccess(ctx context.Context, accessToken string) (*AccessClaims, error)

	// RequireAccess can be installed as HTTP middleware to ensure that the handlers
	// downstream will only be called if the client has supplied a valid Twitch User
	// Access Token in the Authorization header, and only if the user authenticated by
	// that token has been granted a role that meets or exceeds the level of access
	// required by 'role'
	RequireAccess(role Role, next http.Handler) http.Handler

	// GetClaims can be called from the final HTTP handler to retrieve the AccessClaims
	// value that was stashed in the request context by RequireAccess
	GetClaims(req *http.Request) (*AccessClaims, error)
}

// NewClient initializes an HTTP client configured to make requests against the
// golden-vcr/auth server running at the given URL
func NewClient(authUrl string) Client {
	return &client{
		authUrl: authUrl,
	}
}

// client is the standard HTTP implementation of Client
type client struct {
	http.Client
	authUrl string
}

// CheckAccess calls GET /access and parses the response, returning ErrUnauthorized if
// the auth server responds with a 401 error
func (c *client) CheckAccess(ctx context.Context, accessToken string) (*AccessClaims, error) {
	// Prepare a request to GET /access, with our configured URL for the auth server,
	// supplying the provided access token as the value of the Authorization header
	url := c.authUrl + "/access"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("authorization", fmt.Sprintf("Bearer %s", accessToken))

	// Make the request and ensure that it completed successfully
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	// Continue on 200; propagate 401; fail on any other response
	if res.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got response %d from GET %s", res.StatusCode, url)
	}

	// Parse the response body, JSON-formatted, as an AccessClaims struct
	contentType := res.Header.Get("content/type")
	if contentType != "" && !strings.HasPrefix(contentType, "application/json") {
		return nil, fmt.Errorf("got unexpected content-type '%s' from GET %s", contentType, url)
	}
	var claims AccessClaims
	if err := json.NewDecoder(res.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("error decoding response body: %w", err)
	}
	return &claims, nil
}

func (c *client) RequireAccess(role Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		// Require an Authorization header, otherwise return 400
		accessToken := parseAuthorizationHeader(req.Header.Get("authorization"))
		if accessToken == "" {
			http.Error(res, "Twitch user access token must be supplied in Authorization header", http.StatusBadRequest)
			return
		}

		// Call the auth API to validate that we've been given a valid Twitch User
		// Access token, and to identify the user and their level of access in the
		// Golden VCR app
		claims, err := c.CheckAccess(req.Context(), accessToken)
		if err != nil {
			// If the token wasn't accepted by Twitch, propagate it as a 401 error, and
			// treat any other error as a 500
			status := http.StatusInternalServerError
			if errors.Is(err, ErrUnauthorized) {
				status = http.StatusUnauthorized
			}
			http.Error(res, err.Error(), status)
			return
		}

		// Our token is valid: verify that the user has the correct level of access to call
		// this endpoint
		if !claims.Role.meetsOrExceeds(role) {
			http.Error(res, fmt.Sprintf("insufficient access: requires %s; you are %s", role, claims.Role), http.StatusForbidden)
			return
		}

		// We successfully obtained user claims for the access token we've been given;
		// stash those claims in the request context so the handler can read them, and
		// continue handling the request
		ctx := context.WithValue(req.Context(), contextKeyClaims, claims)
		next.ServeHTTP(res, req.WithContext(ctx))
	})
}

func (c *client) GetClaims(req *http.Request) (*AccessClaims, error) {
	value := req.Context().Value(contextKeyClaims)
	if value == nil {
		return nil, fmt.Errorf("could not parse claims: RequireAccess middleware was not installed in request-handler chain")
	}
	claims, ok := value.(*AccessClaims)
	if !ok {
		return nil, fmt.Errorf("value stored in context with key %s was not a valid AccessClaims", contextKeyClaims)
	}
	return claims, nil
}

func parseAuthorizationHeader(value string) string {
	prefix := "Bearer "
	if strings.HasPrefix(value, prefix) {
		return value[len(prefix):]
	}
	return value
}

var _ Client = (*client)(nil)
