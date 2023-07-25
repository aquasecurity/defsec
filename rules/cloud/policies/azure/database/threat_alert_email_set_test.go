package database

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckThreatAlertEmailSet(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "No email address provided for threat alerts",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:       defsecTypes.NewTestMetadata(),
								EmailAddresses: []defsecTypes.StringValue{},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "No email address provided for threat alerts, but alert is disabled",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:       defsecTypes.NewTestMetadata(),
								State:          defsecTypes.String("Disabled", defsecTypes.NewTestMetadata()),
								EmailAddresses: []defsecTypes.StringValue{},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Email address provided for threat alerts",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								EmailAddresses: []defsecTypes.StringValue{
									defsecTypes.String("sample@email.com", defsecTypes.NewTestMetadata()),
								},
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
			results := CheckThreatAlertEmailSet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckThreatAlertEmailSet.Rule().LongID() {
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
