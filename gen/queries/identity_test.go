package queries_test

import (
	"context"
	"testing"

	"github.com/golden-vcr/auth/gen/queries"
	"github.com/golden-vcr/server-common/querytest"
)

func Test_RecordUserLogin(t *testing.T) {
	tx := querytest.PrepareTx(t)
	q := queries.New(tx)

	// We should start with no user identities recorded
	querytest.AssertCount(t, tx, 0, "SELECT COUNT(*) FROM auth.identity")

	// Recording a new user login should record a new identity, and the first/last login
	// timestamps should be identical initially
	q.RecordUserLogin(context.Background(), queries.RecordUserLoginParams{
		TwitchUserID:      "1234",
		TwitchDisplayName: "bungus",
	})
	querytest.AssertCount(t, tx, 1, `
		SELECT COUNT(*) FROM auth.identity
			WHERE twitch_user_id = '1234' AND twitch_display_name = 'bungus'
			AND first_logged_in_at = last_logged_in_at
	`)

	// A subsequent login by the same user with a different display name should update
	// that display name, and last_logged_in_at timestamp should be updated while
	// preserving the original value of first_logged_in_at (TODO: we rely on postgres to
	// update timestamps from now(), which is frozen for the duration of a transaction)
	q.RecordUserLogin(context.Background(), queries.RecordUserLoginParams{
		TwitchUserID:      "1234",
		TwitchDisplayName: "BunGus",
	})
	querytest.AssertCount(t, tx, 1, `
		SELECT COUNT(*) FROM auth.identity WHERE
			twitch_user_id = '1234' AND twitch_display_name = 'BunGus'
			-- AND first_logged_in_at < last_logged_in_at
	`)

	// We should end up with 1 user identity
	querytest.AssertCount(t, tx, 1, "SELECT COUNT(*) FROM auth.identity")
}
