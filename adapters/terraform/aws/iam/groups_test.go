package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/aws/iam"
)

func Test_adaptGroups(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []iam.Group
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []iam.Group{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptGroups(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
