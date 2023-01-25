package provisioner

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/terraform/provisioner"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_LocalExecs(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []provisioner.LocalExec
	}{
		{
			name: "empty",
			terraform: `
resource "null_resource" "example" {
	provisioner "local-exec" {}
}
`,
			expected: []provisioner.LocalExec{
				{
					Metadata:    defsecTypes.NewTestMetadata(),
					Command:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Interpreter: nil,
					WorkingDir:  defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Environment: defsecTypes.MapDefault(make(map[string]string), defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "basic",
			terraform: `
resource "null_resource" "example" {
	provisioner "local-exec" {
		command = "open WFH, '>completed.txt' and print WFH scalar localtime"
		interpreter = ["perl", "-e"]
		working_dir = "/tmp"
		environment = {
			FOO = "bar"
		}
	}
}
`,
			expected: []provisioner.LocalExec{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					Command:  defsecTypes.String("open WFH, '>completed.txt' and print WFH scalar localtime", defsecTypes.NewTestMetadata()),
					Interpreter: []defsecTypes.StringValue{
						defsecTypes.String("perl", defsecTypes.NewTestMetadata()),
						defsecTypes.String("-e", defsecTypes.NewTestMetadata()),
					},
					WorkingDir: defsecTypes.String("/tmp", defsecTypes.NewTestMetadata()),
					Environment: defsecTypes.MapDefault(map[string]string{
						"FOO": "bar",
					}, defsecTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted.LocalExecs)
		})
	}
}
