package sources

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/external"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []external.Source
	}{
		{
			name: "basic",
			terraform: `
data "external" "example" {
}
`,
			expected: []external.Source{
				{
					Metadata:   defsecTypes.NewTestMetadata(),
					Program:    nil,
					WorkingDir: defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Query:      defsecTypes.MapDefault(make(map[string]string), defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "basic",
			terraform: `
data "external" "example" {
	program = ["python", "${path.module}/example-data-source.py"]
	working_dir = "/tmp"
	
	query = {
		# arbitrary map from strings to strings, passed
		# to the external program as the data query.
		id = "abc123"
	}
}
			`,
			expected: []external.Source{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					Program: []defsecTypes.StringValue{
						defsecTypes.String("python", defsecTypes.NewTestMetadata()),
						defsecTypes.String("./example-data-source.py", defsecTypes.NewTestMetadata()),
					},
					WorkingDir: defsecTypes.String("/tmp", defsecTypes.NewTestMetadata()),
					Query: defsecTypes.MapDefault(map[string]string{
						"id": "abc123",
					}, defsecTypes.NewTestMetadata()),
				},
			},
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
