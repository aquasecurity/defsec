package s3

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/s3"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckLoggingIsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    s3.S3
		expected bool
	}{
		{
			name: "S3 bucket logging disabled",
			input: s3.S3{
				Metadata: types.NewTestMetadata(),
				Buckets: []s3.Bucket{
					{
						Metadata: types.NewTestMetadata(),
						ACL:      types.String("private", types.NewTestMetadata()),
						Logging: s3.Logging{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "S3 bucket logging enabled",
			input: s3.S3{
				Metadata: types.NewTestMetadata(),
				Buckets: []s3.Bucket{
					{
						Metadata: types.NewTestMetadata(),
						ACL:      types.String("log-delivery-write", types.NewTestMetadata()),
						Logging: s3.Logging{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
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
			testState.AWS.S3 = test.input
			results := CheckLoggingIsEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckLoggingIsEnabled.Rule().LongID() {
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
