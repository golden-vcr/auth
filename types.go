package auth

import "fmt"

type Role string

const (
	RoleViewer      Role = "viewer"
	RoleBroadcaster Role = "broadcaster"
)

func (r Role) value() int {
	switch r {
	case RoleViewer:
		return 0
	case RoleBroadcaster:
		return 99
	default:
		panic(fmt.Sprintf("unrecognized role: %s", r))
	}
}

func (r Role) meetsOrExceeds(requiredRole Role) bool {
	return r.value() >= requiredRole.value()
}

type UserDetails struct {
	Id          string `json:"id"`
	Login       string `json:"login"`
	DisplayName string `json:"displayName"`
}

type UserTokens struct {
	AccessToken  string   `json:"accessToken"`
	RefreshToken string   `json:"refreshToken"`
	Scopes       []string `json:"scopes"`
}

type AuthState struct {
	LoggedIn        bool         `json:"loggedIn"`
	Role            Role         `json:"role,omitempty"`
	ProfileImageUrl string       `json:"profileImageUrl,omitempty"`
	User            *UserDetails `json:"user,omitempty"`
	Tokens          *UserTokens  `json:"tokens,omitempty"`
	Error           string       `json:"error,omitempty"`
}

type AccessClaims struct {
	User *UserDetails `json:"user"`
	Role Role         `json:"role"`
}
