package provisioner

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/pkg/providers/terraform/provisioner"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/require"
)

var defaultConnection = provisioner.Connection{
	Metadata:       defsecTypes.NewTestMetadata(),
	Type:           defsecTypes.StringDefault("ssh", defsecTypes.NewTestMetadata()),
	Timeout:        defsecTypes.StringDefault("5m", defsecTypes.NewTestMetadata()),
	User:           defsecTypes.StringDefault("root", defsecTypes.NewTestMetadata()),
	Port:           defsecTypes.IntDefault(22, defsecTypes.NewTestMetadata()),
	TargetPlatform: defsecTypes.StringDefault("unix", defsecTypes.NewTestMetadata()),
	ScriptPath:     defsecTypes.StringDefault("/tmp/terraform_%RAND%.sh", defsecTypes.NewTestMetadata()),
	BastionUser:    defsecTypes.StringDefault("root", defsecTypes.NewTestMetadata()),
	BastionPort:    defsecTypes.IntDefault(22, defsecTypes.NewTestMetadata()),
	Agent:          defsecTypes.BoolDefault(true, defsecTypes.NewTestMetadata()),
}

func Test_Connection(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  provisioner.Connection
	}{
		{
			name: "empty",
			terraform: `
resource "null_resource" "example" {
	provisioner "file" { }
}
`,
			expected: defaultConnection,
		},
		{
			name: "inheritance",
			terraform: `
resource "null_resource" "example" {
	connection {
		user = "resource"
	}
	provisioner "file" {
		connection {
			user = "provisioner"
		}
	}
}
`,
			expected: provisioner.Connection{
				Metadata:       defsecTypes.NewTestMetadata(),
				Type:           defsecTypes.StringDefault("ssh", defsecTypes.NewTestMetadata()),
				Timeout:        defsecTypes.StringDefault("5m", defsecTypes.NewTestMetadata()),
				User:           defsecTypes.StringDefault("provisioner", defsecTypes.NewTestMetadata()),
				Port:           defsecTypes.IntDefault(22, defsecTypes.NewTestMetadata()),
				TargetPlatform: defsecTypes.StringDefault("unix", defsecTypes.NewTestMetadata()),
				ScriptPath:     defsecTypes.StringDefault("/tmp/terraform_%RAND%.sh", defsecTypes.NewTestMetadata()),
				BastionUser:    defsecTypes.StringDefault("provisioner", defsecTypes.NewTestMetadata()),
				BastionPort:    defsecTypes.IntDefault(22, defsecTypes.NewTestMetadata()),
				Agent:          defsecTypes.BoolDefault(true, defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "winrm",
			terraform: `
resource "null_resource" "example" {
	provisioner "file" {
		connection {
			type = "winrm"
			insecure = true
		}
	}
}
`,
			expected: provisioner.Connection{
				Metadata:       defsecTypes.NewTestMetadata(),
				Type:           defsecTypes.StringDefault("winrm", defsecTypes.NewTestMetadata()),
				Timeout:        defsecTypes.StringDefault("5m", defsecTypes.NewTestMetadata()),
				User:           defsecTypes.StringDefault("Administrator", defsecTypes.NewTestMetadata()),
				Port:           defsecTypes.IntDefault(5985, defsecTypes.NewTestMetadata()),
				ScriptPath:     defsecTypes.StringDefault("C:/Temp/terraform_%RAND%.cmd", defsecTypes.NewTestMetadata()),
				Insecure:       defsecTypes.BoolDefault(true, defsecTypes.NewTestMetadata()),
				TargetPlatform: defsecTypes.StringDefault("windows", defsecTypes.NewTestMetadata()),
				BastionUser:    defsecTypes.StringDefault("Administrator", defsecTypes.NewTestMetadata()),
				BastionPort:    defsecTypes.IntDefault(5985, defsecTypes.NewTestMetadata()),
				Agent:          defsecTypes.BoolDefault(true, defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			require.Len(t, adapted.Files, 1)
			conn := adapted.Files[0].Connection
			testutil.AssertDefsecEqual(t, test.expected, conn)
		})
	}
}
