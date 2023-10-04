package auth_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golden-vcr/auth"
	authmock "github.com/golden-vcr/auth/mock"
	"github.com/stretchr/testify/assert"
)

func Test_RequireAccess(t *testing.T) {
	// Prepare a mock auth.Client that accepts two tokens, one from a viewer and another
	// from the broadcaster
	c := authmock.NewClient().Allow("viewer-token", auth.RoleViewer, auth.UserDetails{
		Id:          "1234",
		Login:       "someviewer",
		DisplayName: "SomeViewer",
	}).Allow("broadcaster-token", auth.RoleBroadcaster, auth.UserDetails{
		Id:          "31337",
		Login:       "channelowner",
		DisplayName: "ChannelOwner",
	})

	// Prepare an example HTTP request handler that expects to be called after the
	// RequireAccess middleware runs
	echoClaimsIfAuthorized := func(res http.ResponseWriter, req *http.Request) {
		// GetClaims should never return an error so long as RequireAccess was called
		claims, err := auth.GetClaims(req)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		// Echo the claims back at the user in JSON format
		if err := json.NewEncoder(res).Encode(claims); err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
		}
	}

	// Run a series of tests in different configurations and verify that we get the
	// expected results when calling the API as different users
	type apiCall struct {
		token          string
		wantStatus     int
		wantBodySubstr string
	}
	tests := []struct {
		installMiddleware bool
		requiredRole      auth.Role
		calls             []apiCall
	}{
		{
			false,
			auth.RoleViewer,
			[]apiCall{
				{"", http.StatusInternalServerError, "RequireAccess middleware was not installed"},
				{"invalid-token", http.StatusInternalServerError, "RequireAccess middleware was not installed"},
				{"viewer-token", http.StatusInternalServerError, "RequireAccess middleware was not installed"},
				{"broadcaster-token", http.StatusInternalServerError, "RequireAccess middleware was not installed"},
			},
		},
		{
			true,
			auth.RoleViewer,
			[]apiCall{
				{"", http.StatusBadRequest, "Twitch user access token must be supplied in Authorization header"},
				{"invalid-token", http.StatusUnauthorized, "access token was not accepted"},
				{"viewer-token", http.StatusOK, `{"user":{"id":"1234","login":"someviewer","displayName":"SomeViewer"},"role":"viewer"}`},
				{"broadcaster-token", http.StatusOK, `{"user":{"id":"31337","login":"channelowner","displayName":"ChannelOwner"},"role":"broadcaster"}`},
			},
		},
		{
			true,
			auth.RoleBroadcaster,
			[]apiCall{
				{"", http.StatusBadRequest, "Twitch user access token must be supplied in Authorization header"},
				{"invalid-token", http.StatusUnauthorized, "access token was not accepted"},
				{"viewer-token", http.StatusForbidden, "insufficient access: requires broadcaster; you are viewer"},
				{"broadcaster-token", http.StatusOK, `{"user":{"id":"31337","login":"channelowner","displayName":"ChannelOwner"},"role":"broadcaster"}`},
			},
		},
	}
	for _, tt := range tests {
		desc := "without middleware"
		var handler http.Handler = http.HandlerFunc(echoClaimsIfAuthorized)
		if tt.installMiddleware {
			desc = fmt.Sprintf("with middleware requiring %s access", tt.requiredRole)
			handler = auth.RequireAccess(c, tt.requiredRole, handler)
		}

		for _, call := range tt.calls {
			name := fmt.Sprintf("%s, %s should get %d", desc, call.token, call.wantStatus)
			t.Run(name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				if call.token != "" {
					req.Header.Set("authorization", fmt.Sprintf("Bearer %s", call.token))
				}
				res := httptest.NewRecorder()
				handler.ServeHTTP(res, req)

				assert.Equal(t, call.wantStatus, res.Result().StatusCode)

				body, err := io.ReadAll(res.Result().Body)
				assert.NoError(t, err)
				assert.Contains(t, string(body), call.wantBodySubstr)
			})
		}
	}
}
