package authmock

import (
	"context"
	"testing"

	"github.com/golden-vcr/auth"
	"github.com/stretchr/testify/assert"
)

func Test_Client(t *testing.T) {
	c := NewClient().Allow("token-a", auth.RoleViewer, auth.UserDetails{
		Id:          "12345",
		Login:       "usera",
		DisplayName: "UserA",
	}).Allow("token-b", auth.RoleBroadcaster, auth.UserDetails{
		Id:          "16789",
		Login:       "userb",
		DisplayName: "UserB",
	})

	claimsA, err := c.CheckAccess(context.Background(), "token-a")
	assert.NoError(t, err)
	assert.NotNil(t, claimsA)
	assert.Equal(t, auth.RoleViewer, claimsA.Role)
	assert.Equal(t, "12345", claimsA.User.Id)

	claimsB, err := c.CheckAccess(context.Background(), "token-b")
	assert.NoError(t, err)
	assert.NotNil(t, claimsB)
	assert.Equal(t, auth.RoleBroadcaster, claimsB.Role)
	assert.Equal(t, "16789", claimsB.User.Id)

	claimsC, err := c.CheckAccess(context.Background(), "nonexistent-token")
	assert.ErrorIs(t, err, auth.ErrUnauthorized)
	assert.Nil(t, claimsC)
}
