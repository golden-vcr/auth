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
	c := authmock.NewClient().AllowTwitchUserAccessToken("viewer-token", auth.RoleViewer, auth.UserDetails{
		Id:          "1234",
		Login:       "someviewer",
		DisplayName: "SomeViewer",
	}).AllowTwitchUserAccessToken("broadcaster-token", auth.RoleBroadcaster, auth.UserDetails{
		Id:          "31337",
		Login:       "channelowner",
		DisplayName: "ChannelOwner",
	})

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
				{"", http.StatusBadRequest, "Twitch user access token or internal JWT must be supplied in Authorization header"},
				{"invalid-token", http.StatusUnauthorized, "access token was not accepted"},
				{"viewer-token", http.StatusOK, `{"user":{"id":"1234","login":"someviewer","displayName":"SomeViewer"},"role":"viewer"}`},
				{"broadcaster-token", http.StatusOK, `{"user":{"id":"31337","login":"channelowner","displayName":"ChannelOwner"},"role":"broadcaster"}`},
			},
		},
		{
			true,
			auth.RoleBroadcaster,
			[]apiCall{
				{"", http.StatusBadRequest, "Twitch user access token or internal JWT must be supplied in Authorization header"},
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

func Test_RequireAuthority(t *testing.T) {
	// Prepare a mock auth.Client that accepts an ordinary user access token, as well as
	// an authoritative JWT issued to an internal service by the auth server,
	// authorizing access to a specific user's resources
	c := authmock.NewClient().AllowTwitchUserAccessToken("viewer-token", auth.RoleViewer, auth.UserDetails{
		Id:          "1234",
		Login:       "someviewer",
		DisplayName: "SomeViewer",
	}).AllowAuthoritativeJWT("internal-jwt", auth.UserDetails{
		Id:          "5678",
		Login:       "anotherviewer",
		DisplayName: "AnotherViewer",
	})

	// Run a series of tests in different configurations and verify that we get the
	// expected results when calling the API as different users
	tests := []struct {
		token          string
		wantStatus     int
		wantBodySubstr string
	}{
		{
			"",
			http.StatusBadRequest,
			"Internal JWT must be supplied in Authorization header",
		},
		{
			"viewer-token",
			http.StatusUnauthorized,
			"access denied",
		},
		{
			"internal-jwt",
			http.StatusOK,
			`{"user":{"id":"5678","login":"anotherviewer","displayName":"AnotherViewer"},"role":"viewer","authoritative":true}`,
		},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("%s should get %d", tt.token, tt.wantStatus)
		handler := auth.RequireAuthority(c, http.HandlerFunc(echoClaimsIfAuthorized))
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.token != "" {
				req.Header.Set("authorization", fmt.Sprintf("Bearer %s", tt.token))
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)

			assert.Equal(t, tt.wantStatus, res.Result().StatusCode)

			body, err := io.ReadAll(res.Result().Body)
			assert.NoError(t, err)
			assert.Contains(t, string(body), tt.wantBodySubstr)
		})
	}
}

// echoClaimsIfAuthorized simply echoes the claims parsed from the request by the
// middleware which runs before this handler
func echoClaimsIfAuthorized(res http.ResponseWriter, req *http.Request) {
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
