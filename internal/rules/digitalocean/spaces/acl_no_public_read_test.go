package spaces

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/digitalocean/spaces"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				Buckets: []spaces.Bucket{
					{
						Metadata: types2.NewTestMetadata(),
						ACL:      types2.String("public-read", types2.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Space bucket object with public read ACL",
			input: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: types2.NewTestMetadata(),
						ACL:      types2.String("private", types2.NewTestMetadata()),
						Objects: []spaces.Object{
							{
								Metadata: types2.NewTestMetadata(),
								ACL:      types2.String("public-read", types2.NewTestMetadata()),
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
				Buckets: []spaces.Bucket{
					{
						Metadata: types2.NewTestMetadata(),
						ACL:      types2.String("private", types2.NewTestMetadata()),
						Objects: []spaces.Object{
							{
								Metadata: types2.NewTestMetadata(),
								ACL:      types2.String("private", types2.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAclNoPublicRead.Rule().LongID() {
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
