package monitor

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

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
						Metadata: defsecTypes.NewTestMetadata(),
						Locations: []defsecTypes.StringValue{
							defsecTypes.String("eastus", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Locations: []defsecTypes.StringValue{
							defsecTypes.String("eastus", defsecTypes.NewTestMetadata()),
							defsecTypes.String("eastus2", defsecTypes.NewTestMetadata()),
							defsecTypes.String("southcentralus", defsecTypes.NewTestMetadata()),
							defsecTypes.String("westus2", defsecTypes.NewTestMetadata()),
							defsecTypes.String("westus3", defsecTypes.NewTestMetadata()),
							defsecTypes.String("australiaeast", defsecTypes.NewTestMetadata()),
							defsecTypes.String("southeastasia", defsecTypes.NewTestMetadata()),
							defsecTypes.String("northeurope", defsecTypes.NewTestMetadata()),
							defsecTypes.String("swedencentral", defsecTypes.NewTestMetadata()),
							defsecTypes.String("uksouth", defsecTypes.NewTestMetadata()),
							defsecTypes.String("westeurope", defsecTypes.NewTestMetadata()),
							defsecTypes.String("centralus", defsecTypes.NewTestMetadata()),
							defsecTypes.String("northcentralus", defsecTypes.NewTestMetadata()),
							defsecTypes.String("westus", defsecTypes.NewTestMetadata()),
							defsecTypes.String("southafricanorth", defsecTypes.NewTestMetadata()),
							defsecTypes.String("centralindia", defsecTypes.NewTestMetadata()),
							defsecTypes.String("eastasia", defsecTypes.NewTestMetadata()),
							defsecTypes.String("japaneast", defsecTypes.NewTestMetadata()),
							defsecTypes.String("jioindiawest", defsecTypes.NewTestMetadata()),
							defsecTypes.String("koreacentral", defsecTypes.NewTestMetadata()),
							defsecTypes.String("canadacentral", defsecTypes.NewTestMetadata()),
							defsecTypes.String("francecentral", defsecTypes.NewTestMetadata()),
							defsecTypes.String("germanywestcentral", defsecTypes.NewTestMetadata()),
							defsecTypes.String("norwayeast", defsecTypes.NewTestMetadata()),
							defsecTypes.String("switzerlandnorth", defsecTypes.NewTestMetadata()),
							defsecTypes.String("uaenorth", defsecTypes.NewTestMetadata()),
							defsecTypes.String("brazilsouth", defsecTypes.NewTestMetadata()),
							defsecTypes.String("centralusstage", defsecTypes.NewTestMetadata()),
							defsecTypes.String("eastusstage", defsecTypes.NewTestMetadata()),
							defsecTypes.String("eastus2stage", defsecTypes.NewTestMetadata()),
							defsecTypes.String("northcentralusstage", defsecTypes.NewTestMetadata()),
							defsecTypes.String("southcentralusstage", defsecTypes.NewTestMetadata()),
							defsecTypes.String("westusstage", defsecTypes.NewTestMetadata()),
							defsecTypes.String("westus2stage", defsecTypes.NewTestMetadata()),
							defsecTypes.String("asia", defsecTypes.NewTestMetadata()),
							defsecTypes.String("asiapacific", defsecTypes.NewTestMetadata()),
							defsecTypes.String("australia", defsecTypes.NewTestMetadata()),
							defsecTypes.String("brazil", defsecTypes.NewTestMetadata()),
							defsecTypes.String("canada", defsecTypes.NewTestMetadata()),
							defsecTypes.String("europe", defsecTypes.NewTestMetadata()),
							defsecTypes.String("global", defsecTypes.NewTestMetadata()),
							defsecTypes.String("india", defsecTypes.NewTestMetadata()),
							defsecTypes.String("japan", defsecTypes.NewTestMetadata()),
							defsecTypes.String("uk", defsecTypes.NewTestMetadata()),
							defsecTypes.String("unitedstates", defsecTypes.NewTestMetadata()),
							defsecTypes.String("eastasiastage", defsecTypes.NewTestMetadata()),
							defsecTypes.String("southeastasiastage", defsecTypes.NewTestMetadata()),
							defsecTypes.String("centraluseuap", defsecTypes.NewTestMetadata()),
							defsecTypes.String("eastus2euap", defsecTypes.NewTestMetadata()),
							defsecTypes.String("westcentralus", defsecTypes.NewTestMetadata()),
							defsecTypes.String("southafricawest", defsecTypes.NewTestMetadata()),
							defsecTypes.String("australiacentral", defsecTypes.NewTestMetadata()),
							defsecTypes.String("australiacentral2", defsecTypes.NewTestMetadata()),
							defsecTypes.String("australiasoutheast", defsecTypes.NewTestMetadata()),
							defsecTypes.String("japanwest", defsecTypes.NewTestMetadata()),
							defsecTypes.String("jioindiacentral", defsecTypes.NewTestMetadata()),
							defsecTypes.String("koreasouth", defsecTypes.NewTestMetadata()),
							defsecTypes.String("southindia", defsecTypes.NewTestMetadata()),
							defsecTypes.String("westindia", defsecTypes.NewTestMetadata()),
							defsecTypes.String("canadaeast", defsecTypes.NewTestMetadata()),
							defsecTypes.String("francesouth", defsecTypes.NewTestMetadata()),
							defsecTypes.String("germanynorth", defsecTypes.NewTestMetadata()),
							defsecTypes.String("norwaywest", defsecTypes.NewTestMetadata()),
							defsecTypes.String("swedensouth", defsecTypes.NewTestMetadata()),
							defsecTypes.String("switzerlandwest", defsecTypes.NewTestMetadata()),
							defsecTypes.String("ukwest", defsecTypes.NewTestMetadata()),
							defsecTypes.String("uaecentral", defsecTypes.NewTestMetadata()),
							defsecTypes.String("brazilsoutheast", defsecTypes.NewTestMetadata()),
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
