package database

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckThreatAlertEmailToOwner(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "MS SQL Server alert account admins disabled",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:           types2.NewTestMetadata(),
								EmailAccountAdmins: types2.Bool(false, types2.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MS SQL Server alert account admins enabled",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:           types2.NewTestMetadata(),
								EmailAccountAdmins: types2.Bool(true, types2.NewTestMetadata()),
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
			results := CheckThreatAlertEmailToOwner.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckThreatAlertEmailToOwner.Rule().LongID() {
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
