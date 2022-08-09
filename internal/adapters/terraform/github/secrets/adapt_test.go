package secrets

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/github"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []github.EnvironmentSecret
	}{
		{
			name: "basic",
			terraform: `
resource "github_actions_environment_secret" "example" {
}
`,
			expected: []github.EnvironmentSecret{
				{
					Metadata:       types2.NewTestMetadata(),
					Environment:    types2.String("", types2.NewTestMetadata()),
					SecretName:     types2.String("", types2.NewTestMetadata()),
					PlainTextValue: types2.String("", types2.NewTestMetadata()),
					EncryptedValue: types2.String("", types2.NewTestMetadata()),
					Repository:     types2.String("", types2.NewTestMetadata()),
				},
			},
		},
		{
			name: "basic",
			terraform: `
resource "github_actions_environment_secret" "example" {
    secret_name     = "a"
	plaintext_value = "b"
	environment     = "c"
	encrypted_value = "d"
	repository      = "e"
}
`,
			expected: []github.EnvironmentSecret{
				{
					Metadata:       types2.NewTestMetadata(),
					SecretName:     types2.String("a", types2.NewTestMetadata()),
					PlainTextValue: types2.String("b", types2.NewTestMetadata()),
					Environment:    types2.String("c", types2.NewTestMetadata()),
					EncryptedValue: types2.String("d", types2.NewTestMetadata()),
					Repository:     types2.String("e", types2.NewTestMetadata()),
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
