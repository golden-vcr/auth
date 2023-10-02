package server

import (
	"github.com/gorilla/mux"
)

type Server struct {
	channelUserId string
	client        TwitchClient
	q             Queries
}

func New(channelUserId string, twitchClientId string, twitchClientSecret string, q Queries) *Server {
	return &Server{
		channelUserId: channelUserId,
		client:        NewTwitchClient(twitchClientId, twitchClientSecret),
		q:             q,
	}
}

func (s *Server) RegisterRoutes(r *mux.Router) {
	// Authentication endpoints: allows the user to establish their identity by granting
	// our app a User Access Token via Twitch
	r.Path("/login").Methods("POST").HandlerFunc(s.handleLogin)
	r.Path("/refresh").Methods("POST").HandlerFunc(s.handleRefresh)
	r.Path("/logout").Methods("POST").HandlerFunc(s.handleLogout)

	// Access endpoints: allows other APIs to determine whether the user identified by a
	// User Access Token (supplied in the Authorization header) should be authorized to
	// use the app
	r.Path("/access").Methods("GET").HandlerFunc(s.handleGetAccess)
}
