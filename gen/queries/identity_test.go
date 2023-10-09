package queries_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/golden-vcr/auth/gen/queries"
	"github.com/golden-vcr/server-common/querytest"
)

func Test_RecordUserLogin(t *testing.T) {
	tx := querytest.PrepareTx(t)
	q := queries.New(tx)

	// We should start with no user identities recorded
	assertCount(t, tx, 0, "SELECT COUNT(*) FROM auth.identity")

	// Recording a new user login should record a new identity, and the first/last login
	// timestamps should be identical initially
	q.RecordUserLogin(context.Background(), queries.RecordUserLoginParams{
		TwitchUserID:      "1234",
		TwitchDisplayName: "bungus",
	})
	assertCount(t, tx, 1, `
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
	assertCount(t, tx, 1, `
		SELECT COUNT(*) FROM auth.identity WHERE
			twitch_user_id = '1234' AND twitch_display_name = 'BunGus'
			-- AND first_logged_in_at < last_logged_in_at
	`)

	// We should end up with 1 user identity
	assertCount(t, tx, 1, "SELECT COUNT(*) FROM auth.identity")
}

func assertCount(t *testing.T, tx *sql.Tx, wantCount int, query string, args ...any) {
	row := tx.QueryRow(query, args...)

	var count int
	err := row.Scan(&count)
	if err == nil && count != wantCount {
		err = fmt.Errorf("expected count of %d; got %d", wantCount, count)
	}

	if err != nil {
		t.Logf("With query:")
		for _, line := range strings.Split(query, "\n") {
			t.Logf("  %s", line)
		}
		if len(args) > 0 {
			t.Logf("With args:")
			for i, value := range args {
				t.Logf(" $%d: %v", i+1, value)
			}
		}
		t.Fatalf(err.Error())
	}
}
