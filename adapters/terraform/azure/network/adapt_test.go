package network

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/azure/network"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  network.Network
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: network.Network{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptWatcherLogs(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []network.NetworkWatcherFlowLog
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []network.NetworkWatcherFlowLog{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptWatcherLogs(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptWatcherLog(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  network.NetworkWatcherFlowLog
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: network.NetworkWatcherFlowLog{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptWatcherLog(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
