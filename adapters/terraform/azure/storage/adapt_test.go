package storage

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/azure/storage"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  storage.Storage
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: storage.Storage{},
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

func Test_adaptAccounts(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []storage.Account
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []storage.Account{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted, _, _ := adaptAccounts(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptAccount(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  storage.Account
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: storage.Account{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptAccount(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptContainer(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  storage.Container
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: storage.Container{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptContainer(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptNetworkRule(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  storage.NetworkRule
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: storage.NetworkRule{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptNetworkRule(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
