package spaces

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/digitalocean/spaces"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckAclNoPublicRead(t *testing.T) {
	tests := []struct {
		name     string
		input    spaces.Spaces
		expected bool
	}{
		{
			name: "Space bucket with public read ACL",
			input: spaces.Spaces{
				Metadata: types.NewTestMetadata(),
				Buckets: []spaces.Bucket{
					{
						Metadata: types.NewTestMetadata(),
						ACL:      types.String("public-read", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Space bucket object with public read ACL",
			input: spaces.Spaces{
				Metadata: types.NewTestMetadata(),
				Buckets: []spaces.Bucket{
					{
						Metadata: types.NewTestMetadata(),
						ACL:      types.String("private", types.NewTestMetadata()),
						Objects: []spaces.Object{
							{
								Metadata: types.NewTestMetadata(),
								ACL:      types.String("public-read", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Space bucket and bucket object with private ACL",
			input: spaces.Spaces{
				Metadata: types.NewTestMetadata(),
				Buckets: []spaces.Bucket{
					{
						Metadata: types.NewTestMetadata(),
						ACL:      types.String("private", types.NewTestMetadata()),
						Objects: []spaces.Object{
							{
								Metadata: types.NewTestMetadata(),
								ACL:      types.String("private", types.NewTestMetadata()),
							},
						},
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
			results := CheckAclNoPublicRead.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckAclNoPublicRead.Rule().LongID() {
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
