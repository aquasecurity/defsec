package vpc

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/aws/vpc"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  vpc.VPC
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: vpc.VPC{},
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

func Test_adaptDefaultVPCs(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []vpc.DefaultVPC
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []vpc.DefaultVPC{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDefaultVPCs(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSGRule(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  vpc.SecurityGroupRule
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: vpc.SecurityGroupRule{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSGRule(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptNetworkACLRule(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  vpc.NetworkACLRule
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: vpc.NetworkACLRule{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptNetworkACLRule(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
