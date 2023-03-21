package rds

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				Instances: []rds.Instance{
					{
						Metadata:             defsecTypes.NewTestMetadata(),
						ReplicationSourceARN: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						Encryption: rds.Encryption{
							Metadata:       defsecTypes.NewTestMetadata(),
							EncryptStorage: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Instance with encrypted storage",
			input: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:             defsecTypes.NewTestMetadata(),
						ReplicationSourceARN: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						Encryption: rds.Encryption{
							Metadata:       defsecTypes.NewTestMetadata(),
							EncryptStorage: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEncryptInstanceStorageData.Rule().LongID() {
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
