package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_EmbeddingPolicies(t *testing.T) {
	entries, err := EmbeddedPolicyFileSystem.ReadDir(".")
	require.NoError(t, err)
	assert.Greater(t, len(entries), 0)
}

func Test_EmbeddingLibraries(t *testing.T) {
	entries, err := EmbeddedLibraryFileSystem.ReadDir(".")
	require.NoError(t, err)
	assert.Greater(t, len(entries), 0)
}
