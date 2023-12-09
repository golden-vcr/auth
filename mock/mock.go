package authmock

import (
	"context"

	"github.com/golden-vcr/auth"
)

type Client struct {
	validTokens map[string]*auth.AccessClaims
}

func NewClient() *Client {
	return &Client{
		validTokens: make(map[string]*auth.AccessClaims),
	}
}

func (c *Client) AllowTwitchUserAccessToken(token string, role auth.Role, user auth.UserDetails) *Client {
	c.validTokens[token] = &auth.AccessClaims{
		Role: role,
		User: &user,
	}
	return c
}

func (c *Client) AllowAuthoritativeJWT(token string, user auth.UserDetails) *Client {
	c.validTokens[token] = &auth.AccessClaims{
		Role:          auth.RoleViewer,
		User:          &user,
		Authoritative: true,
	}
	return c
}

func (c *Client) CheckAccess(ctx context.Context, accessToken string) (*auth.AccessClaims, error) {
	claims, ok := c.validTokens[accessToken]
	if !ok {
		return nil, auth.ErrUnauthorized
	}
	return claims, nil
}

var _ auth.Client = (*Client)(nil)
