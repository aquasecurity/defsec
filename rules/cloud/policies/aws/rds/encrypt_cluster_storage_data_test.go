package rds

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptClusterStorageData(t *testing.T) {
	tests := []struct {
		name     string
		input    rds.RDS
		expected bool
	}{
		{
			name: "RDS Cluster with storage encryption disabled",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       defsecTypes.NewTestMetadata(),
							EncryptStorage: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							KMSKeyID:       defsecTypes.String("kms-key", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Cluster with storage encryption enabled but missing KMS key",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       defsecTypes.NewTestMetadata(),
							EncryptStorage: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							KMSKeyID:       defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Cluster with storage encryption enabled and KMS key provided",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       defsecTypes.NewTestMetadata(),
							EncryptStorage: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							KMSKeyID:       defsecTypes.String("kms-key", defsecTypes.NewTestMetadata()),
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
			results := CheckEncryptClusterStorageData.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEncryptClusterStorageData.Rule().LongID() {
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
