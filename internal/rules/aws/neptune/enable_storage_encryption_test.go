package neptune

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/neptune"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableStorageEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    neptune.Neptune
		expected bool
	}{
		{
			name: "Neptune Cluster without storage encryption",
			input: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata:         types.NewTestMetadata(),
						StorageEncrypted: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Neptune Cluster with storage encryption",
			input: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata:         types.NewTestMetadata(),
						StorageEncrypted: types.Bool(true, types.NewTestMetadata()),
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
			results := CheckEnableStorageEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableStorageEncryption.Rule().LongID() {
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
