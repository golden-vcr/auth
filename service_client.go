package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/golden-vcr/server-common/hmac"
)

// ServiceClient allows a trusted internal service running in the backend to contact the
// auth server to request a service token, i.e. a JWT that authorizes other backend APIs
// to access the state associated with a specific viewer
type ServiceClient interface {
	RequestServiceToken(ctx context.Context, payload ServiceTokenRequest) (string, error)
}

// NewServiceClient initializes an auth.ServiceClient. secret is the shared secret,
// known only to internal services, that's used to generate an HMAC signature when
// sending service token requests to the auth server, thereby allowing it to validate
// that the request is coming from an authorized internal service
func NewServiceClient(authUrl string, secret string) ServiceClient {
	return &serviceClient{
		authUrl: authUrl,
		signer:  hmac.NewSigner(secret),
	}
}

// serviceClient is the standard implementation of auth.ServiceClient that contacts the
// auth server to request a JWT
type serviceClient struct {
	http.Client
	authUrl string

	// signer allows us to sign requests using the symmetric secret that's known only to
	// us and to the auth server
	signer hmac.Signer
}

func (c *serviceClient) RequestServiceToken(ctx context.Context, payload ServiceTokenRequest) (string, error) {
	// JSON-encode the payload that defines the details of the request
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Initialize a request to POST /service-token, for a JWT that will provide
	// short-lived, viewer-level access to the desired user
	url := c.authUrl + "/service-token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payloadBytes))
	if err != nil {
		return "", err
	}

	// Sign the request with the shared HMAC secret, proving to the auth server that we
	// are a trusted internal service with the authority to modify the state of
	// arbitrary users: i.e. we're acting in response to a Twitch webhook event, IRC
	// message, etc. that we trust to identify the target user faithfully
	req, err = c.signer.Sign(req, payloadBytes)
	if err != nil {
		return "", err
	}

	// Make the request to the auth server, and ensure that it's completed
	res, err := c.Do(req)
	if err != nil {
		return "", err
	}

	// Check the response: if the JWT was successfully issued, we'll get a 200 response
	// that carries the token string in the response body, with content-type
	// 'application/jwt'
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		suffix := ""
		if body, err := io.ReadAll(res.Body); err == nil {
			suffix = fmt.Sprintf(": %s", body)
		}
		return "", fmt.Errorf("got response %d from POST %s%s", res.StatusCode, url, suffix)
	}
	contentType := res.Header.Get("content-type")
	if !strings.HasPrefix(contentType, "application/jwt") {
		return "", fmt.Errorf("got unexpected content-type '%s' from POST %s", contentType, url)
	}
	tokenBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body from %s: %w", url, err)
	}

	// Return the JWT string directly: internal APIs should just pass it around
	// opaquely; only auth.Client should need to parse it as a JWT and examine its
	// claims etc
	return string(tokenBytes), nil
}

var _ ServiceClient = (*serviceClient)(nil)
