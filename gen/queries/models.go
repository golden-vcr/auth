// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.20.0

package queries

import (
	"time"
)

// Details about a user, authenticated via Twitch, who has interacted with the Golden VCR app at some point.
type AuthIdentity struct {
	// Text-formatted integer identifying this user in the Twitch API.
	TwitchUserID string
	// Last known username by which this user was known, formatted for display.
	TwitchDisplayName string
	// Timestamp when the user first logged in at goldenvcr.com.
	FirstLoggedInAt time.Time
	// Timestamp when the user most recently logged in at goldenvcr.com.
	LastLoggedInAt time.Time
}