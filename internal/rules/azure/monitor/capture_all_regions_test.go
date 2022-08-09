package monitor

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/monitor"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: types2.NewTestMetadata(),
						Locations: []types2.StringValue{
							types2.String("eastus", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log profile captures all regions",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: types2.NewTestMetadata(),
						Locations: []types2.StringValue{
							types2.String("eastus", types2.NewTestMetadata()),
							types2.String("eastus2", types2.NewTestMetadata()),
							types2.String("southcentralus", types2.NewTestMetadata()),
							types2.String("westus2", types2.NewTestMetadata()),
							types2.String("westus3", types2.NewTestMetadata()),
							types2.String("australiaeast", types2.NewTestMetadata()),
							types2.String("southeastasia", types2.NewTestMetadata()),
							types2.String("northeurope", types2.NewTestMetadata()),
							types2.String("swedencentral", types2.NewTestMetadata()),
							types2.String("uksouth", types2.NewTestMetadata()),
							types2.String("westeurope", types2.NewTestMetadata()),
							types2.String("centralus", types2.NewTestMetadata()),
							types2.String("northcentralus", types2.NewTestMetadata()),
							types2.String("westus", types2.NewTestMetadata()),
							types2.String("southafricanorth", types2.NewTestMetadata()),
							types2.String("centralindia", types2.NewTestMetadata()),
							types2.String("eastasia", types2.NewTestMetadata()),
							types2.String("japaneast", types2.NewTestMetadata()),
							types2.String("jioindiawest", types2.NewTestMetadata()),
							types2.String("koreacentral", types2.NewTestMetadata()),
							types2.String("canadacentral", types2.NewTestMetadata()),
							types2.String("francecentral", types2.NewTestMetadata()),
							types2.String("germanywestcentral", types2.NewTestMetadata()),
							types2.String("norwayeast", types2.NewTestMetadata()),
							types2.String("switzerlandnorth", types2.NewTestMetadata()),
							types2.String("uaenorth", types2.NewTestMetadata()),
							types2.String("brazilsouth", types2.NewTestMetadata()),
							types2.String("centralusstage", types2.NewTestMetadata()),
							types2.String("eastusstage", types2.NewTestMetadata()),
							types2.String("eastus2stage", types2.NewTestMetadata()),
							types2.String("northcentralusstage", types2.NewTestMetadata()),
							types2.String("southcentralusstage", types2.NewTestMetadata()),
							types2.String("westusstage", types2.NewTestMetadata()),
							types2.String("westus2stage", types2.NewTestMetadata()),
							types2.String("asia", types2.NewTestMetadata()),
							types2.String("asiapacific", types2.NewTestMetadata()),
							types2.String("australia", types2.NewTestMetadata()),
							types2.String("brazil", types2.NewTestMetadata()),
							types2.String("canada", types2.NewTestMetadata()),
							types2.String("europe", types2.NewTestMetadata()),
							types2.String("global", types2.NewTestMetadata()),
							types2.String("india", types2.NewTestMetadata()),
							types2.String("japan", types2.NewTestMetadata()),
							types2.String("uk", types2.NewTestMetadata()),
							types2.String("unitedstates", types2.NewTestMetadata()),
							types2.String("eastasiastage", types2.NewTestMetadata()),
							types2.String("southeastasiastage", types2.NewTestMetadata()),
							types2.String("centraluseuap", types2.NewTestMetadata()),
							types2.String("eastus2euap", types2.NewTestMetadata()),
							types2.String("westcentralus", types2.NewTestMetadata()),
							types2.String("southafricawest", types2.NewTestMetadata()),
							types2.String("australiacentral", types2.NewTestMetadata()),
							types2.String("australiacentral2", types2.NewTestMetadata()),
							types2.String("australiasoutheast", types2.NewTestMetadata()),
							types2.String("japanwest", types2.NewTestMetadata()),
							types2.String("jioindiacentral", types2.NewTestMetadata()),
							types2.String("koreasouth", types2.NewTestMetadata()),
							types2.String("southindia", types2.NewTestMetadata()),
							types2.String("westindia", types2.NewTestMetadata()),
							types2.String("canadaeast", types2.NewTestMetadata()),
							types2.String("francesouth", types2.NewTestMetadata()),
							types2.String("germanynorth", types2.NewTestMetadata()),
							types2.String("norwaywest", types2.NewTestMetadata()),
							types2.String("swedensouth", types2.NewTestMetadata()),
							types2.String("switzerlandwest", types2.NewTestMetadata()),
							types2.String("ukwest", types2.NewTestMetadata()),
							types2.String("uaecentral", types2.NewTestMetadata()),
							types2.String("brazilsoutheast", types2.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckCaptureAllRegions.Rule().LongID() {
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
