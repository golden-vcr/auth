package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseAuthorizationHeader(t *testing.T) {
	assert.Equal(t, "", parseAuthorizationHeader(""))
	assert.Equal(t, "foobar", parseAuthorizationHeader("foobar"))
	assert.Equal(t, "foobar", parseAuthorizationHeader("Bearer foobar"))
	assert.Equal(t, "Entirely-Different-Prefix foobar", parseAuthorizationHeader("Entirely-Different-Prefix foobar"))
}
