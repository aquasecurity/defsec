package lambda

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/providers/aws/lambda"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  lambda.Lambda
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: lambda.Lambda{},
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
