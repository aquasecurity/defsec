package s3

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/s3"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    s3.S3
		expected bool
	}{
		{
			name: "S3 Bucket missing KMS key",
			input: s3.S3{
				Metadata: types.NewTestMetadata(),
				Buckets: []s3.Bucket{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: s3.Encryption{
							Metadata: types.Metadata{},
							Enabled:  types.Bool(true, types.NewTestMetadata()),
							KMSKeyId: types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "S3 Bucket with KMS key",
			input: s3.S3{
				Metadata: types.NewTestMetadata(),
				Buckets: []s3.Bucket{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: s3.Encryption{
							Metadata: types.Metadata{},
							Enabled:  types.Bool(true, types.NewTestMetadata()),
							KMSKeyId: types.String("some-sort-of-key", types.NewTestMetadata()),
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
			results := CheckEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEncryptionCustomerKey.Rule().LongID() {
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
