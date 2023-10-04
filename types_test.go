package auth

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Role_meetsOrExceeds(t *testing.T) {
	tests := []struct {
		requiredRole Role
		r            Role
		want         bool
	}{
		{RoleViewer, RoleViewer, true},
		{RoleViewer, RoleBroadcaster, true},
		{RoleBroadcaster, RoleViewer, false},
		{RoleBroadcaster, RoleBroadcaster, true},
	}
	for _, tt := range tests {
		verb := "is"
		if !tt.want {
			verb = "is not"
		}
		name := fmt.Sprintf("%s %s sufficient to access %s", tt.r, verb, tt.requiredRole)
		t.Run(name, func(t *testing.T) {
			got := tt.r.meetsOrExceeds(tt.requiredRole)
			assert.Equal(t, tt.want, got)
		})
	}
}
