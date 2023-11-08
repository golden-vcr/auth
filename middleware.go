package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// contextKeyClaims is the key under which our HTTP middleware will stash a valid
// *auth.AccessClaims value once authorization succeeds
var contextKeyClaims = "gvcr-claims"

// RequireAccess can be installed as HTTP middleware to ensure that the handlers
// downstream will only be called if the client has supplied a valid Twitch User Access
// Token in the Authorization header, and only if the user authenticated by that token
// has been granted a role that meets or exceeds the level of access required by 'role'
func RequireAccess(c Client, role Role, next http.Handler) http.Handler {
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

// GetClaims can be called from the final HTTP handler to retrieve the AccessClaims
// value that was stashed in the request context by RequireAccess
func GetClaims(req *http.Request) (*AccessClaims, error) {
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

// GetToken returns the authorization header value that was passed to the request
func GetToken(req *http.Request) string {
	return parseAuthorizationHeader(req.Header.Get("authorization"))
}

func parseAuthorizationHeader(value string) string {
	prefix := "Bearer "
	if strings.HasPrefix(value, prefix) {
		return value[len(prefix):]
	}
	return value
}
