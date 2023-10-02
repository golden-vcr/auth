package server

import (
	"context"

	"github.com/golden-vcr/auth/gen/queries"
)

type Queries interface {
	RecordUserLogin(ctx context.Context, arg queries.RecordUserLoginParams) error
}
