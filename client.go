package auth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golden-vcr/server-common/entry"
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
func NewClient(ctx context.Context, authUrl string) (Client, error) {
	c := &client{
		authUrl:     authUrl,
		jwtIssuer:   "https://goldenvcr.com/api/auth",
		keyCacheTTL: 10 * time.Minute,
		keyCache:    make(map[string]rsa.PublicKey),
	}
	if err := c.fetchJWKS(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// client is the standard HTTP implementation of Client
type client struct {
	http.Client
	authUrl   string
	jwtIssuer string

	keyCacheTTL       time.Duration
	keyCache          map[string]rsa.PublicKey
	keyCacheExpiresAt time.Time
	keyCacheMu        sync.RWMutex
}

// CheckAccess calls GET /access and parses the response, returning ErrUnauthorized if
// the auth server responds with a 401 error
func (c *client) CheckAccess(ctx context.Context, accessToken string) (*AccessClaims, error) {
	// First check to see if the token is a JWT that was issued by the auth service: if
	// so, and if we can resolve the public key matching its 'kid' header and
	// successfully verify that the key was issued by the auth service, then we can
	// accept its claims client-side
	token, err := c.parseAndVerifyJWT(ctx, accessToken)
	if err == nil {
		jwtClaims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("failed to parse claims from JWT")
		}
		gvcrService := jwtClaims["gvcr_service"].(string)
		twitchUserId := jwtClaims["twitch_user_id"].(string)
		if twitchUserId == "" {
			return nil, fmt.Errorf("JWT is missing 'twitch_user_id' claim")
		}
		twitchUserLogin := jwtClaims["twitch_user_login"].(string)
		if twitchUserLogin == "" {
			return nil, fmt.Errorf("JWT is missing 'twitch_user_login' claim")
		}
		twitchDisplayName := jwtClaims["twitch_display_name"].(string)
		if twitchDisplayName == "" {
			return nil, fmt.Errorf("JWT is missing 'twitch_display_name' claim")
		}
		return &AccessClaims{
			Role: RoleViewer,
			User: &UserDetails{
				Id:          twitchUserId,
				Login:       twitchUserLogin,
				DisplayName: twitchDisplayName,
			},
			Authoritative: gvcrService != "",
		}, nil
	}

	// parseAndVerifyJWT returned an error: if the error indicates that the input token
	// wasn't a JWT or was issued by some other authority, continue to the fallback path
	// of calling GET /access. For all other errors, abort.
	if !errors.Is(err, ErrForeignToken) {
		return nil, err
	}

	// Prepare a request to GET /access, with our configured URL for the auth server,
	// supplying the provided access token as the value of the Authorization header
	url := c.authUrl + "/access"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req = entry.ConveyRequestId(ctx, req)
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

var _ Client = (*client)(nil)
