package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/google/iam"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  iam.IAM
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: iam.IAM{},
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
