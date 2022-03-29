package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/google/compute"
)

func Test_adaptSSLPolicies(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []compute.SSLPolicy
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []compute.SSLPolicy{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSSLPolicies(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
