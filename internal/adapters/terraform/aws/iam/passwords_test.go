package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptPasswordPolicy(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  iam.PasswordPolicy
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: iam.PasswordPolicy{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptPasswordPolicy(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
