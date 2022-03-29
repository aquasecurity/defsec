package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/aws/iam"
)

func Test_adaptPolicies(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []iam.Policy
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []iam.Policy{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptPolicies(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
