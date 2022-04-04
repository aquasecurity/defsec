package monitor

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/azure/monitor"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptLogProfile(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  monitor.LogProfile
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_monitor_log_profile" "example" {
				categories = [
					"Action",
					"Delete",
					"Write",
				]

				retention_policy {
				  enabled = true
				  days    = 365
				}

				locations = [
					"eastus",
					"eastus2",
					"southcentralus"
				]
			  }
`,
			expected: monitor.LogProfile{
				Metadata: types.NewTestMetadata(),
				Categories: []types.StringValue{
					types.String("Action", types.NewTestMetadata()),
					types.String("Delete", types.NewTestMetadata()),
					types.String("Write", types.NewTestMetadata()),
				},
				RetentionPolicy: monitor.RetentionPolicy{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(true, types.NewTestMetadata()),
					Days:     types.Int(365, types.NewTestMetadata()),
				},
				Locations: []types.StringValue{
					types.String("eastus", types.NewTestMetadata()),
					types.String("eastus2", types.NewTestMetadata()),
					types.String("southcentralus", types.NewTestMetadata()),
				},
			},
		},
		{
			name: "default",
			terraform: `
			resource "azurerm_monitor_log_profile" "example" {
			  }
`,
			expected: monitor.LogProfile{
				Metadata: types.NewTestMetadata(),
				RetentionPolicy: monitor.RetentionPolicy{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(false, types.NewTestMetadata()),
					Days:     types.Int(0, types.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptLogProfile(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_monitor_log_profile" "example" {
		categories = [
			"Action",
			"Delete",
			"Write",
		]

		retention_policy {
		  enabled = true
		  days    = 365
		}

		locations = [
			"eastus",
			"eastus2",
			"southcentralus"
		]
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.LogProfiles, 1)
	logProfile := adapted.LogProfiles[0]

	assert.Equal(t, 3, logProfile.Categories[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, logProfile.Categories[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, logProfile.RetentionPolicy.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, logProfile.RetentionPolicy.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, logProfile.RetentionPolicy.Days.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, logProfile.RetentionPolicy.Days.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, logProfile.Locations[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, logProfile.Locations[0].GetMetadata().Range().GetEndLine())
}
