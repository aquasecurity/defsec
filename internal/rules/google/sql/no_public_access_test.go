package sql

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/sql"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Instance settings set with IPv4 enabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: types2.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: types2.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   types2.NewTestMetadata(),
								EnableIPv4: types2.Bool(true, types2.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance settings set with IPv4 disabled but public CIDR in authorized networks",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: types2.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: types2.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   types2.NewTestMetadata(),
								EnableIPv4: types2.Bool(false, types2.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name types2.StringValue
									CIDR types2.StringValue
								}{
									{
										CIDR: types2.String("0.0.0.0/0", types2.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance settings set with IPv4 disabled and private CIDR",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: types2.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: types2.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   types2.NewTestMetadata(),
								EnableIPv4: types2.Bool(false, types2.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name types2.StringValue
									CIDR types2.StringValue
								}{
									{
										CIDR: types2.String("10.0.0.1/24", types2.NewTestMetadata()),
									},
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
			testState.Google.SQL = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
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
