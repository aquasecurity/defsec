package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"

	"github.com/aquasecurity/defsec/providers/aws/iam"
)

func Test_adaptUsers(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []iam.User
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []iam.User{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptUsers(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
