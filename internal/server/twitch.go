package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/nicklaw5/helix/v2"
)

var ErrFailedToInitializeTwitchClient = errors.New("failed to initialize twitch client")
var ErrTwitchReturnedUnauthorized = errors.New("got 401 response from Twitch API")

type TwitchClient interface {
	GetUserAccessToken(ctx context.Context, code string, redirectUri string) (*helix.AccessCredentials, error)
	RefreshUserAccessToken(ctx context.Context, refreshToken string) (*helix.AccessCredentials, error)
	RevokeUserAccessToken(ctx context.Context, accessToken string) error
	ResolveUserDetailsFromAccessToken(ctx context.Context, accessToken string) (*helix.User, error)
}

func NewTwitchClient(clientId string, clientSecret string) TwitchClient {
	return &twitchClient{
		clientId:     clientId,
		clientSecret: clientSecret,
	}
}

type twitchClient struct {
	clientId     string
	clientSecret string
}

func (t *twitchClient) GetUserAccessToken(ctx context.Context, code string, redirectUri string) (*helix.AccessCredentials, error) {
	client, err := helix.NewClientWithContext(ctx, &helix.Options{
		ClientID:     t.clientId,
		ClientSecret: t.clientSecret,
		RedirectURI:  redirectUri,
	})
	if err != nil {
		return nil, ErrFailedToInitializeTwitchClient
	}

	r, err := client.RequestUserAccessToken(code)
	if err != nil {
		return nil, fmt.Errorf("failed to get user access token: %w", err)
	}
	if r.StatusCode != http.StatusOK {
		if r.StatusCode == http.StatusUnauthorized {
			return nil, ErrTwitchReturnedUnauthorized
		}
		return nil, fmt.Errorf("got %d response from RequestUserAccessToken: %s", r.StatusCode, r.ErrorMessage)
	}
	return &r.Data, nil
}

func (t *twitchClient) RefreshUserAccessToken(ctx context.Context, refreshToken string) (*helix.AccessCredentials, error) {
	client, err := helix.NewClientWithContext(ctx, &helix.Options{
		ClientID:     t.clientId,
		ClientSecret: t.clientSecret,
	})
	if err != nil {
		return nil, ErrFailedToInitializeTwitchClient
	}

	r, err := client.RefreshUserAccessToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh access token: %w", err)
	}
	if r.StatusCode != http.StatusOK {
		if r.StatusCode == http.StatusUnauthorized {
			return nil, ErrTwitchReturnedUnauthorized
		}
		return nil, fmt.Errorf("got %d response from RefreshUserAccessToken: %s\n", r.StatusCode, r.ErrorMessage)
	}
	return &r.Data, nil
}

func (t *twitchClient) RevokeUserAccessToken(ctx context.Context, accessToken string) error {
	client, err := helix.NewClientWithContext(ctx, &helix.Options{
		ClientID: t.clientId,
	})
	if err != nil {
		return ErrFailedToInitializeTwitchClient
	}

	r, err := client.RevokeUserAccessToken(accessToken)
	if err != nil {
		return fmt.Errorf("failed to revoke user access token: %w", err)
	}
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("got %d response from RevokeUserAccessToken: %s", r.StatusCode, r.ErrorMessage)
	}
	return nil
}

func (t *twitchClient) ResolveUserDetailsFromAccessToken(ctx context.Context, accessToken string) (*helix.User, error) {
	client, err := helix.NewClientWithContext(ctx, &helix.Options{
		ClientID:     t.clientId,
		ClientSecret: t.clientSecret,
	})
	if err != nil {
		return nil, ErrFailedToInitializeTwitchClient
	}
	client.SetUserAccessToken(accessToken)

	r, err := client.GetUsers(&helix.UsersParams{})
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusOK {
		if r.StatusCode == http.StatusUnauthorized {
			return nil, ErrTwitchReturnedUnauthorized
		}
		return nil, fmt.Errorf("got response %d from Users: %s", r.StatusCode, r.ErrorMessage)
	}
	if len(r.Data.Users) != 1 {
		return nil, fmt.Errorf("GetUsers returned %d results; expected 1", len(r.Data.Users))
	}
	return &r.Data.Users[0], nil
}

var _ TwitchClient = (*twitchClient)(nil)
