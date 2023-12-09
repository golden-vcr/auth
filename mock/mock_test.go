package authmock

import (
	"context"
	"testing"

	"github.com/golden-vcr/auth"
	"github.com/stretchr/testify/assert"
)

func Test_Client(t *testing.T) {
	c := NewClient().AllowTwitchUserAccessToken("token-a", auth.RoleViewer, auth.UserDetails{
		Id:          "12345",
		Login:       "usera",
		DisplayName: "UserA",
	}).AllowTwitchUserAccessToken("token-b", auth.RoleBroadcaster, auth.UserDetails{
		Id:          "16789",
		Login:       "userb",
		DisplayName: "UserB",
	}).AllowAuthoritativeJWT("jwt-c", auth.UserDetails{
		Id:          "55555",
		Login:       "userc",
		DisplayName: "UserC",
	})

	claimsA, err := c.CheckAccess(context.Background(), "token-a")
	assert.NoError(t, err)
	assert.NotNil(t, claimsA)
	assert.Equal(t, auth.RoleViewer, claimsA.Role)
	assert.Equal(t, "12345", claimsA.User.Id)
	assert.False(t, claimsA.Authoritative)

	claimsB, err := c.CheckAccess(context.Background(), "token-b")
	assert.NoError(t, err)
	assert.NotNil(t, claimsB)
	assert.Equal(t, auth.RoleBroadcaster, claimsB.Role)
	assert.Equal(t, "16789", claimsB.User.Id)
	assert.False(t, claimsB.Authoritative)

	claimsC, err := c.CheckAccess(context.Background(), "jwt-c")
	assert.NoError(t, err)
	assert.NotNil(t, claimsC)
	assert.Equal(t, auth.RoleViewer, claimsC.Role)
	assert.Equal(t, "55555", claimsC.User.Id)
	assert.True(t, claimsC.Authoritative)

	claimsD, err := c.CheckAccess(context.Background(), "nonexistent-token")
	assert.ErrorIs(t, err, auth.ErrUnauthorized)
	assert.Nil(t, claimsD)
}
