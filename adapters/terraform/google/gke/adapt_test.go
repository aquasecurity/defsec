package gke

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/google/gke"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  gke.GKE
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: gke.GKE{},
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

func Test_adaptNodeConfig(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  gke.NodeConfig
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: gke.NodeConfig{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptNodeConfig(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptMasterAuth(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  gke.MasterAuth
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: gke.MasterAuth{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptMasterAuth(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
