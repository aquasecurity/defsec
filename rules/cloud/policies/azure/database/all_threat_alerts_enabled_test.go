package database

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAllThreatAlertsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "MS SQL server alerts for SQL injection disabled",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								DisabledAlerts: []defsecTypes.StringValue{
									defsecTypes.String("Sql_Injection", defsecTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MS SQL server all alerts enabled",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:       defsecTypes.NewTestMetadata(),
								DisabledAlerts: []defsecTypes.StringValue{},
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
			results := CheckAllThreatAlertsEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAllThreatAlertsEnabled.Rule().LongID() {
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
