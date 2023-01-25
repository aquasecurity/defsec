package provisioner

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/provisioner"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_Files(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []provisioner.File
	}{
		{
			name: "empty",
			terraform: `
resource "null_resource" "example" {
	provisioner "file" { }
}
`,
			expected: []provisioner.File{
				{
					Metadata:    defsecTypes.NewTestMetadata(),
					Connection:  defaultConnection,
					Source:      defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Content:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Destination: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "source",
			terraform: `
resource "null_resource" "example" {
	provisioner "file" {
		source      = "conf/myapp.conf"
		destination = "/etc/myapp.conf"
	}
}
`,
			expected: []provisioner.File{
				{
					Metadata:    defsecTypes.NewTestMetadata(),
					Connection:  defaultConnection,
					Source:      defsecTypes.String("conf/myapp.conf", defsecTypes.NewTestMetadata()),
					Content:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Destination: defsecTypes.String("/etc/myapp.conf", defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "source",
			terraform: `
resource "null_resource" "example" {
	provisioner "file" {
		content      = "12345"
		destination = "/etc/myapp.conf"
	}
}
`,
			expected: []provisioner.File{
				{
					Metadata:    defsecTypes.NewTestMetadata(),
					Connection:  defaultConnection,
					Source:      defsecTypes.String("", defsecTypes.NewTestMetadata()),
					Content:     defsecTypes.String("12345", defsecTypes.NewTestMetadata()),
					Destination: defsecTypes.String("/etc/myapp.conf", defsecTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted.Files)
		})
	}
}
