package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golden-vcr/auth/gen/queries"
	"github.com/gorilla/mux"
	"github.com/nicklaw5/helix/v2"
	"github.com/stretchr/testify/assert"
)

var MockTwitchScopes = []string{"user:read:follows"}

const (
	MockTwitchAuthorizationCode       = "mock-twitch-authorization-code"
	MockTwitchAccessToken             = "mock-twitch-access-token-01"
	MockTwitchAccessTokenAfterRefresh = "mock-twitch-access-token-02"
	MockTwitchRefreshToken            = "mock-twitch-refresh-token"

	MockTwitchUserId      = "8675309"
	MockTwitchLogin       = "jenny"
	MockTwitchDisplayName = "Jenny"
)

func Test_Server_handleLogin(t *testing.T) {
	tests := []struct {
		name              string
		code              string
		redirectUri       string
		q                 *mockAuthQueries
		wantStatus        int
		wantBody          string
		wantLoginRecorded bool
	}{
		{
			"login with valid auth code produces 200 and logged-in AuthState",
			MockTwitchAuthorizationCode,
			"https://any-redirect-uri.biz/whatever",
			&mockAuthQueries{},
			http.StatusOK,
			`{"loggedIn":true,"user":{"id":"8675309","login":"jenny","displayName":"Jenny"},"tokens":{"accessToken":"mock-twitch-access-token-01","refreshToken":"mock-twitch-refresh-token","scopes":["user:read:follows"]}}`,
			true,
		},
		{
			"login with invalid auth code produces 401 and logged-out AuthState",
			"invalid-authorization-code",
			"https://any-redirect-uri.biz/whatever",
			&mockAuthQueries{},
			http.StatusUnauthorized,
			`{"loggedIn":false,"error":"mock error"}`,
			false,
		},
		{
			"login with missing auth code produces 400",
			"",
			"https://any-redirect-uri.biz/whatever",
			&mockAuthQueries{},
			http.StatusBadRequest,
			`'code' URL parameter is required`,
			false,
		},
		{
			"login with missing redirect_uri produces 400",
			MockTwitchAuthorizationCode,
			"",
			&mockAuthQueries{},
			http.StatusBadRequest,
			`'redirect_uri' URL parameter is required`,
			false,
		},
	}
	for _, tt := range tests {
		s := &Server{
			client: &authenticationTestClient{},
			q:      tt.q,
		}
		r := mux.NewRouter()
		s.RegisterRoutes(r)

		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		params := req.URL.Query()
		if tt.code != "" {
			params.Add("code", tt.code)
		}
		if tt.redirectUri != "" {
			params.Add("redirect_uri", tt.redirectUri)
		}
		req.URL.RawQuery = params.Encode()
		res := httptest.NewRecorder()
		r.ServeHTTP(res, req)

		b, err := io.ReadAll(res.Body)
		assert.NoError(t, err)
		body := strings.TrimSuffix(string(b), "\n")
		assert.Equal(t, tt.wantStatus, res.Code)
		assert.Equal(t, tt.wantBody, body)

		if tt.wantLoginRecorded {
			assert.Len(t, tt.q.executed, 1)
			assert.Equal(t, MockTwitchUserId, tt.q.executed[0].TwitchUserID)
			assert.Equal(t, MockTwitchDisplayName, tt.q.executed[0].TwitchDisplayName)
		} else {
			assert.Len(t, tt.q.executed, 0)
		}
	}
}

func Test_Server_handleRefresh(t *testing.T) {
	tests := []struct {
		name              string
		authHeaderValue   string
		q                 *mockAuthQueries
		wantStatus        int
		wantBody          string
		wantLoginRecorded bool
	}{
		{
			"refresh with valid token produces 200 and logged-in AuthState",
			fmt.Sprintf("Bearer %s", MockTwitchRefreshToken),
			&mockAuthQueries{},
			http.StatusOK,
			`{"loggedIn":true,"user":{"id":"8675309","login":"jenny","displayName":"Jenny"},"tokens":{"accessToken":"mock-twitch-access-token-02","refreshToken":"mock-twitch-refresh-token","scopes":["user:read:follows"]}}`,
			true,
		},
		{
			"'Bearer' prefix in Authorization header is optional",
			MockTwitchRefreshToken,
			&mockAuthQueries{},
			http.StatusOK,
			`{"loggedIn":true,"user":{"id":"8675309","login":"jenny","displayName":"Jenny"},"tokens":{"accessToken":"mock-twitch-access-token-02","refreshToken":"mock-twitch-refresh-token","scopes":["user:read:follows"]}}`,
			true,
		},
		{
			"refresh with invalid token produces 401 and logged-out AuthState",
			"invalid-refresh-token",
			&mockAuthQueries{},
			http.StatusUnauthorized,
			`{"loggedIn":false,"error":"mock error"}`,
			false,
		},
		{
			"refresh with missing Authorization header produces 400 and logged-out AuthState",
			"",
			&mockAuthQueries{},
			http.StatusBadRequest,
			`Twitch refresh token must be supplied in Authorization header`,
			false,
		},
	}
	for _, tt := range tests {
		s := &Server{
			client: &authenticationTestClient{},
			q:      tt.q,
		}
		r := mux.NewRouter()
		s.RegisterRoutes(r)

		req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
		if tt.authHeaderValue != "" {
			req.Header.Set("Authorization", tt.authHeaderValue)
		}
		res := httptest.NewRecorder()
		r.ServeHTTP(res, req)

		b, err := io.ReadAll(res.Body)
		assert.NoError(t, err)
		body := strings.TrimSuffix(string(b), "\n")
		assert.Equal(t, tt.wantStatus, res.Code)
		assert.Equal(t, tt.wantBody, body)

		if tt.wantLoginRecorded {
			assert.Len(t, tt.q.executed, 1)
			assert.Equal(t, MockTwitchUserId, tt.q.executed[0].TwitchUserID)
			assert.Equal(t, MockTwitchDisplayName, tt.q.executed[0].TwitchDisplayName)
		} else {
			assert.Len(t, tt.q.executed, 0)
		}
	}
}

func Test_Server_handleLogout(t *testing.T) {
	tests := []struct {
		name             string
		accessToken      string
		client           *authenticationTestClient
		wantStatus       int
		wantBody         string
		wantTokenRevoked bool
	}{
		{
			"logout with valid token produces 200 and logged-out AuthState",
			MockTwitchAccessToken,
			&authenticationTestClient{},
			http.StatusOK,
			`{"loggedIn":false}`,
			true,
		},
		{
			"logout with invalid token produces 401 and logged-out AuthState",
			"invalid-access-token",
			&authenticationTestClient{},
			http.StatusUnauthorized,
			`{"loggedIn":false,"error":"mock error"}`,
			false,
		},
		{
			"logout with missing token produces a 400 error",
			"",
			&authenticationTestClient{},
			http.StatusBadRequest,
			`Twitch user access token must be supplied in Authorization header`,
			false,
		},
	}
	for _, tt := range tests {
		s := &Server{
			client: tt.client,
			q:      &mockAuthQueries{},
		}
		r := mux.NewRouter()
		s.RegisterRoutes(r)

		req := httptest.NewRequest(http.MethodPost, "/logout", nil)
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

		tokenWasRevoked := tt.client.hasTokenBeenRevoked(tt.accessToken)
		assert.Equal(t, tt.wantTokenRevoked, tokenWasRevoked)
	}
}

type authenticationTestClient struct {
	revokedTokens []string
}

func (m *authenticationTestClient) hasTokenBeenRevoked(token string) bool {
	for _, t := range m.revokedTokens {
		if t == token {
			return true
		}
	}
	return false
}

func (m *authenticationTestClient) GetUserAccessToken(ctx context.Context, code string, redirectUri string) (*helix.AccessCredentials, error) {
	if redirectUri == "" {
		return nil, fmt.Errorf("mock error")
	}
	if code != MockTwitchAuthorizationCode {
		return nil, fmt.Errorf("mock error")
	}
	return &helix.AccessCredentials{
		AccessToken:  MockTwitchAccessToken,
		RefreshToken: MockTwitchRefreshToken,
		Scopes:       MockTwitchScopes,
	}, nil
}

func (m *authenticationTestClient) RefreshUserAccessToken(ctx context.Context, refreshToken string) (*helix.AccessCredentials, error) {
	if refreshToken != MockTwitchRefreshToken {
		return nil, fmt.Errorf("mock error")
	}
	return &helix.AccessCredentials{
		AccessToken:  MockTwitchAccessTokenAfterRefresh,
		RefreshToken: MockTwitchRefreshToken,
		Scopes:       MockTwitchScopes,
	}, nil
}

func (m *authenticationTestClient) RevokeUserAccessToken(ctx context.Context, accessToken string) error {
	if accessToken != MockTwitchAccessToken && accessToken != MockTwitchAccessTokenAfterRefresh {
		return fmt.Errorf("mock error")
	}
	if m.hasTokenBeenRevoked(accessToken) {
		return fmt.Errorf("mock error")
	}
	m.revokedTokens = append(m.revokedTokens, accessToken)
	return nil
}

func (m *authenticationTestClient) ResolveUserDetailsFromAccessToken(ctx context.Context, accessToken string) (*helix.User, error) {
	if accessToken != MockTwitchAccessToken && accessToken != MockTwitchAccessTokenAfterRefresh {
		return nil, fmt.Errorf("mock error")
	}
	if m.hasTokenBeenRevoked(accessToken) {
		return nil, fmt.Errorf("mock error")
	}
	return &helix.User{
		ID:          MockTwitchUserId,
		Login:       MockTwitchLogin,
		DisplayName: MockTwitchDisplayName,
	}, nil
}

var _ TwitchClient = (*authenticationTestClient)(nil)

type mockAuthQueries struct {
	shouldFail bool
	executed   []queries.RecordUserLoginParams
}

func (m *mockAuthQueries) RecordUserLogin(ctx context.Context, arg queries.RecordUserLoginParams) error {
	if m.shouldFail {
		return fmt.Errorf("mock db error")
	}
	m.executed = append(m.executed, arg)
	return nil
}

var _ Queries = (*mockAuthQueries)(nil)
