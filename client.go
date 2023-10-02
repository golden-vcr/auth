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

// Client represents an HTTP client that can call the auth server's GET /access endpoint
// in order to verify a user's level of access
type Client interface {
	// CheckAccess uses the provided Twitch User Access token to identify the user and
	// ascertain what role they have been granted for access control: if error is
	// non-nil, the access token is valid and the user's identity is verified
	CheckAccess(ctx context.Context, accessToken string) (*AccessClaims, error)
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
	if !strings.HasPrefix(contentType, "application/json") {
		return nil, fmt.Errorf("got unexpected content-type '%s' from GET %s", contentType, url)
	}
	var claims AccessClaims
	if err := json.NewDecoder(res.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("error decoding response body: %w", err)
	}
	return &claims, nil
}

var _ Client = (*client)(nil)
