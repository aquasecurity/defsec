package secrets

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/github"
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
					Metadata:       types.NewTestMetadata(),
					Environment:    types.String("", types.NewTestMetadata()),
					SecretName:     types.String("", types.NewTestMetadata()),
					PlainTextValue: types.String("", types.NewTestMetadata()),
					EncryptedValue: types.String("", types.NewTestMetadata()),
					Repository:     types.String("", types.NewTestMetadata()),
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
					Metadata:       types.NewTestMetadata(),
					SecretName:     types.String("a", types.NewTestMetadata()),
					PlainTextValue: types.String("b", types.NewTestMetadata()),
					Environment:    types.String("c", types.NewTestMetadata()),
					EncryptedValue: types.String("d", types.NewTestMetadata()),
					Repository:     types.String("e", types.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
