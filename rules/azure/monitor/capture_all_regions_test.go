package monitor

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/monitor"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckCaptureAllRegions(t *testing.T) {
	tests := []struct {
		name     string
		input    monitor.Monitor
		expected bool
	}{
		{
			name: "Log profile captures only eastern US region",
			input: monitor.Monitor{
				Metadata: types.NewTestMetadata(),
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: types.NewTestMetadata(),
						Locations: []types.StringValue{
							types.String("eastus", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log profile captures all regions",
			input: monitor.Monitor{
				Metadata: types.NewTestMetadata(),
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: types.NewTestMetadata(),
						Locations: []types.StringValue{
							types.String("eastus", types.NewTestMetadata()),
							types.String("eastus2", types.NewTestMetadata()),
							types.String("southcentralus", types.NewTestMetadata()),
							types.String("westus2", types.NewTestMetadata()),
							types.String("westus3", types.NewTestMetadata()),
							types.String("australiaeast", types.NewTestMetadata()),
							types.String("southeastasia", types.NewTestMetadata()),
							types.String("northeurope", types.NewTestMetadata()),
							types.String("swedencentral", types.NewTestMetadata()),
							types.String("uksouth", types.NewTestMetadata()),
							types.String("westeurope", types.NewTestMetadata()),
							types.String("centralus", types.NewTestMetadata()),
							types.String("northcentralus", types.NewTestMetadata()),
							types.String("westus", types.NewTestMetadata()),
							types.String("southafricanorth", types.NewTestMetadata()),
							types.String("centralindia", types.NewTestMetadata()),
							types.String("eastasia", types.NewTestMetadata()),
							types.String("japaneast", types.NewTestMetadata()),
							types.String("jioindiawest", types.NewTestMetadata()),
							types.String("koreacentral", types.NewTestMetadata()),
							types.String("canadacentral", types.NewTestMetadata()),
							types.String("francecentral", types.NewTestMetadata()),
							types.String("germanywestcentral", types.NewTestMetadata()),
							types.String("norwayeast", types.NewTestMetadata()),
							types.String("switzerlandnorth", types.NewTestMetadata()),
							types.String("uaenorth", types.NewTestMetadata()),
							types.String("brazilsouth", types.NewTestMetadata()),
							types.String("centralusstage", types.NewTestMetadata()),
							types.String("eastusstage", types.NewTestMetadata()),
							types.String("eastus2stage", types.NewTestMetadata()),
							types.String("northcentralusstage", types.NewTestMetadata()),
							types.String("southcentralusstage", types.NewTestMetadata()),
							types.String("westusstage", types.NewTestMetadata()),
							types.String("westus2stage", types.NewTestMetadata()),
							types.String("asia", types.NewTestMetadata()),
							types.String("asiapacific", types.NewTestMetadata()),
							types.String("australia", types.NewTestMetadata()),
							types.String("brazil", types.NewTestMetadata()),
							types.String("canada", types.NewTestMetadata()),
							types.String("europe", types.NewTestMetadata()),
							types.String("global", types.NewTestMetadata()),
							types.String("india", types.NewTestMetadata()),
							types.String("japan", types.NewTestMetadata()),
							types.String("uk", types.NewTestMetadata()),
							types.String("unitedstates", types.NewTestMetadata()),
							types.String("eastasiastage", types.NewTestMetadata()),
							types.String("southeastasiastage", types.NewTestMetadata()),
							types.String("centraluseuap", types.NewTestMetadata()),
							types.String("eastus2euap", types.NewTestMetadata()),
							types.String("westcentralus", types.NewTestMetadata()),
							types.String("southafricawest", types.NewTestMetadata()),
							types.String("australiacentral", types.NewTestMetadata()),
							types.String("australiacentral2", types.NewTestMetadata()),
							types.String("australiasoutheast", types.NewTestMetadata()),
							types.String("japanwest", types.NewTestMetadata()),
							types.String("jioindiacentral", types.NewTestMetadata()),
							types.String("koreasouth", types.NewTestMetadata()),
							types.String("southindia", types.NewTestMetadata()),
							types.String("westindia", types.NewTestMetadata()),
							types.String("canadaeast", types.NewTestMetadata()),
							types.String("francesouth", types.NewTestMetadata()),
							types.String("germanynorth", types.NewTestMetadata()),
							types.String("norwaywest", types.NewTestMetadata()),
							types.String("swedensouth", types.NewTestMetadata()),
							types.String("switzerlandwest", types.NewTestMetadata()),
							types.String("ukwest", types.NewTestMetadata()),
							types.String("uaecentral", types.NewTestMetadata()),
							types.String("brazilsoutheast", types.NewTestMetadata()),
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
			testState.Azure.Monitor = test.input
			results := CheckCaptureAllRegions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckCaptureAllRegions.Rule().LongID() {
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
