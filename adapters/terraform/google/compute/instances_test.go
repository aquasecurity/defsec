package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/google/compute"
)

func Test_adaptInstances(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []compute.Instance
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []compute.Instance{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptInstances(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
