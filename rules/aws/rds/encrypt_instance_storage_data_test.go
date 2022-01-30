package rds

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/rds"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptInstanceStorageData(t *testing.T) {
	tests := []struct {
		name     string
		input    rds.RDS
		expected bool
	}{
		{
			name: "RDS Instance with unencrypted storage",
			input: rds.RDS{
				Metadata: types.NewTestMetadata(),
				Instances: []rds.Instance{
					{
						Metadata:             types.NewTestMetadata(),
						ReplicationSourceARN: types.String("", types.NewTestMetadata()),
						Encryption: rds.Encryption{
							Metadata:       types.NewTestMetadata(),
							EncryptStorage: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Instance with encrypted storage",
			input: rds.RDS{
				Metadata: types.NewTestMetadata(),
				Instances: []rds.Instance{
					{
						Metadata:             types.NewTestMetadata(),
						ReplicationSourceARN: types.String("", types.NewTestMetadata()),
						Encryption: rds.Encryption{
							Metadata:       types.NewTestMetadata(),
							EncryptStorage: types.Bool(true, types.NewTestMetadata()),
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
			testState.AWS.RDS = test.input
			results := CheckEncryptInstanceStorageData.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEncryptInstanceStorageData.Rule().LongID() {
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
