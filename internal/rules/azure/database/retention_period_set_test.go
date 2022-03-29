package database

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRetentionPeriodSet(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "MS SQL server auditing policy with retention period of 30 days",
			input: database.Database{
				Metadata: types.NewTestMetadata(),
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: types.NewTestMetadata(),
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{
							{
								Metadata:        types.NewTestMetadata(),
								RetentionInDays: types.Int(30, types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MS SQL server auditing policy with retention period of 90 days",
			input: database.Database{
				Metadata: types.NewTestMetadata(),
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: types.NewTestMetadata(),
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{
							{
								Metadata:        types.NewTestMetadata(),
								RetentionInDays: types.Int(90, types.NewTestMetadata()),
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
			testState.Azure.Database = test.input
			results := CheckRetentionPeriodSet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRetentionPeriodSet.Rule().LongID() {
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
