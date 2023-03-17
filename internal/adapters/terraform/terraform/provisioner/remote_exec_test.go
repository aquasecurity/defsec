package provisioner

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/terraform/provisioner"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_RemoteExecs(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []provisioner.RemoteExec
	}{
		{
			name: "empty",
			terraform: `
resource "null_resource" "example" {
	provisioner "remote-exec" {}
}
`,
			expected: []provisioner.RemoteExec{
				{
					Metadata:   defsecTypes.NewTestMetadata(),
					Connection: defaultConnection,
					Inline:     nil,
					Script:     defsecTypes.StringDefault("", defsecTypes.NewTestMetadata()),
					Scripts:    nil,
				},
			},
		},
		{
			name: "inline",
			terraform: `
resource "null_resource" "example" {
	provisioner "remote-exec" {
		inline = [
			"whoami",
		]
	}
}
`,
			expected: []provisioner.RemoteExec{
				{
					Metadata:   defsecTypes.NewTestMetadata(),
					Connection: defaultConnection,
					Inline: []defsecTypes.StringValue{
						defsecTypes.String("whoami", defsecTypes.NewTestMetadata()),
					},
					Script:  defsecTypes.StringDefault("", defsecTypes.NewTestMetadata()),
					Scripts: nil,
				},
			},
		},
		{
			name: "scripts",
			terraform: `
resource "null_resource" "example" {
	provisioner "remote-exec" {
		scripts = [
			"/tmp/somescript.sh",
		]
	}
}
`,
			expected: []provisioner.RemoteExec{
				{
					Metadata:   defsecTypes.NewTestMetadata(),
					Connection: defaultConnection,
					Inline:     nil,
					Script:     defsecTypes.StringDefault("", defsecTypes.NewTestMetadata()),
					Scripts: []defsecTypes.StringValue{
						defsecTypes.String("/tmp/somescript.sh", defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "script",
			terraform: `
resource "null_resource" "example" {
	provisioner "remote-exec" {
		script ="/tmp/somescript.sh"
	}
}
`,
			expected: []provisioner.RemoteExec{
				{
					Metadata:   defsecTypes.NewTestMetadata(),
					Connection: defaultConnection,
					Inline:     nil,
					Script:     defsecTypes.String("/tmp/somescript.sh", defsecTypes.NewTestMetadata()),
					Scripts:    nil,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted.RemoteExecs)
		})
	}
}
