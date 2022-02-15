package rds

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/rds"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckBackupRetentionSpecified(t *testing.T) {
	tests := []struct {
		name     string
		input    rds.RDS
		expected bool
	}{
		{
			name: "RDS Cluster with 1 retention day (default)",
			input: rds.RDS{
				Metadata: types.NewTestMetadata(),
				Clusters: []rds.Cluster{
					{
						Metadata:                  types.NewTestMetadata(),
						ReplicationSourceARN:      types.String("", types.NewTestMetadata()),
						BackupRetentionPeriodDays: types.Int(1, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Instance with 1 retention day (default)",
			input: rds.RDS{
				Metadata: types.NewTestMetadata(),
				Instances: []rds.Instance{
					{
						Metadata:                  types.NewTestMetadata(),
						ReplicationSourceARN:      types.String("", types.NewTestMetadata()),
						BackupRetentionPeriodDays: types.Int(1, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Cluster with 5 retention days",
			input: rds.RDS{
				Metadata: types.NewTestMetadata(),
				Clusters: []rds.Cluster{
					{
						Metadata:                  types.NewTestMetadata(),
						ReplicationSourceARN:      types.String("", types.NewTestMetadata()),
						BackupRetentionPeriodDays: types.Int(5, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "RDS Instance with 5 retention days",
			input: rds.RDS{
				Metadata: types.NewTestMetadata(),
				Instances: []rds.Instance{
					{
						Metadata:                  types.NewTestMetadata(),
						ReplicationSourceARN:      types.String("", types.NewTestMetadata()),
						BackupRetentionPeriodDays: types.Int(5, types.NewTestMetadata()),
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
			results := CheckBackupRetentionSpecified.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckBackupRetentionSpecified.Rule().LongID() {
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
