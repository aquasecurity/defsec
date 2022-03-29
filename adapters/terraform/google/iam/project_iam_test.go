package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/google/iam"
)

func Test_AdaptMember(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  iam.Member
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: iam.Member{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := AdaptMember(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_AdaptBinding(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  iam.Binding
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: iam.Binding{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := AdaptBinding(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
