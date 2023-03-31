package rdb

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/rdb"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckBackupRetentionSpecified(t *testing.T) {
	tests := []struct {
		name     string
		input    rdb.RDB
		expected bool
	}{
		{
			name: "RDB Instance with 1 retention day (default)",
			input: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:                  defsecTypes.NewTestMetadata(),
						BackupRetentionPeriodDays: defsecTypes.Int(1, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "RDB Instance with 5 retention days",
			input: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:                  defsecTypes.NewTestMetadata(),
						BackupRetentionPeriodDays: defsecTypes.Int(5, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.RDB = test.input
			results := CheckBackupRetentionSpecified.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckBackupRetentionSpecified.Rule().LongID() {
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
