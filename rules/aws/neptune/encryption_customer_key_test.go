package neptune

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/neptune"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    neptune.Neptune
		expected bool
	}{
		{
			name: "Neptune Cluster missing KMS key",
			input: neptune.Neptune{
				Metadata: types.NewTestMetadata(),
				Clusters: []neptune.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						KMSKeyID: types.String("", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Neptune Cluster encrypted with KMS key",
			input: neptune.Neptune{
				Metadata: types.NewTestMetadata(),
				Clusters: []neptune.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						KMSKeyID: types.String("some-kms-key", types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.Neptune = test.input
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
