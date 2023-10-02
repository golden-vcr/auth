package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/nicklaw5/helix/v2"
	"github.com/stretchr/testify/assert"
)

func Test_Server_handleGetAccess(t *testing.T) {
	channelUserId := "1337"
	tests := []struct {
		name        string
		client      *accessTestClient
		accessToken string
		wantStatus  int
		wantBody    string
	}{
		{
			"ordinary user with valid token gets viewer-level access",
			&accessTestClient{
				usersByAccessToken: map[string]helix.User{
					"alices-fake-access-token": {
						ID:          "12345",
						Login:       "alice",
						DisplayName: "alice",
					},
				},
			},
			"alices-fake-access-token",
			http.StatusOK,
			`{"user":{"id":"12345","login":"alice","displayName":"alice"},"role":"viewer"}`,
		},
		{
			"user matching channelUserId gets broadcaster-level access",
			&accessTestClient{
				usersByAccessToken: map[string]helix.User{
					"channel-owner-access-token": {
						ID:          channelUserId,
						Login:       "channelowner",
						DisplayName: "ChannelOwner",
					},
				},
			},
			"channel-owner-access-token",
			http.StatusOK,
			`{"user":{"id":"1337","login":"channelowner","displayName":"ChannelOwner"},"role":"broadcaster"}`,
		},
		{
			"invalid access token results in 401 error",
			&accessTestClient{},
			"invalid-access-token",
			http.StatusUnauthorized,
			`got 401 response from Twitch API`,
		},
		{
			"missing access token results in 400 error",
			&accessTestClient{},
			"",
			http.StatusBadRequest,
			`Twitch user access token must be supplied in Authorization header`,
		},
	}
	for _, tt := range tests {
		s := &Server{
			channelUserId: channelUserId,
			client:        tt.client,
			q:             &mockAuthQueries{},
		}
		r := mux.NewRouter()
		s.RegisterRoutes(r)

		req := httptest.NewRequest(http.MethodGet, "/access", nil)
		if tt.accessToken != "" {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tt.accessToken))
		}
		res := httptest.NewRecorder()
		r.ServeHTTP(res, req)

		b, err := io.ReadAll(res.Body)
		assert.NoError(t, err)
		body := strings.TrimSuffix(string(b), "\n")
		assert.Equal(t, tt.wantStatus, res.Code)
		assert.Equal(t, tt.wantBody, body)
	}
}

type accessTestClient struct {
	usersByAccessToken map[string]helix.User
}

func (m *accessTestClient) GetUserAccessToken(ctx context.Context, code string, redirectUri string) (*helix.AccessCredentials, error) {
	return nil, fmt.Errorf("not mocked")
}

func (m *accessTestClient) RefreshUserAccessToken(ctx context.Context, refreshToken string) (*helix.AccessCredentials, error) {
	return nil, fmt.Errorf("not mocked")
}

func (m *accessTestClient) RevokeUserAccessToken(ctx context.Context, accessToken string) error {
	return fmt.Errorf("not mocked")
}

func (m *accessTestClient) ResolveUserDetailsFromAccessToken(ctx context.Context, accessToken string) (*helix.User, error) {
	found, ok := m.usersByAccessToken[accessToken]
	if !ok {
		return nil, ErrTwitchReturnedUnauthorized
	}
	return &found, nil
}

var _ TwitchClient = (*accessTestClient)(nil)
