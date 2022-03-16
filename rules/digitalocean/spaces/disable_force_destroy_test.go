package spaces

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/digitalocean/spaces"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckDisableForceDestroy(t *testing.T) {
	tests := []struct {
		name     string
		input    spaces.Spaces
		expected bool
	}{
		{
			name: "Space bucket force destroy enabled",
			input: spaces.Spaces{
				Metadata: types.NewTestMetadata(),
				Buckets: []spaces.Bucket{
					{
						Metadata:     types.NewTestMetadata(),
						ForceDestroy: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Space bucket force destroy disabled",
			input: spaces.Spaces{
				Metadata: types.NewTestMetadata(),
				Buckets: []spaces.Bucket{
					{
						Metadata:     types.NewTestMetadata(),
						ForceDestroy: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.DigitalOcean.Spaces = test.input
			results := CheckDisableForceDestroy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckDisableForceDestroy.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
