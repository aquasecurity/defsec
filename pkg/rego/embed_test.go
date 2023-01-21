package rego

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/open-policy-agent/opa/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_EmbeddedLoading(t *testing.T) {

	rules := rules.GetFrameworkRules()
	var found bool
	for _, rule := range rules {
		if rule.Rule().RegoPackage != "" {
			found = true
		}
	}
	assert.True(t, found, "no embedded rego policies were registered as rules")
}

func Test_RegisterRegoRules(t *testing.T) {
	var testCases = []struct {
		name          string
		inputPolicy   string
		expectedError bool
	}{
		{
			name: "happy path old single schema",
			inputPolicy: `# METADATA
# title: "dummy title"
# description: "some description"
# scope: package
# schemas:
# - input: schema["input"]
# custom:
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS1234
deny[res]{
	res := true
}`,
		},
		{
			name: "happy path new single schema",
			inputPolicy: `# METADATA
# title: "dummy title"
# description: "some description"
# scope: package
# schemas:
# - input: schema["dockerfile"]
# custom:
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS1234
deny[res]{
	res := true
}`,
		},
		{
			name: "happy path new multiple schemas",
			inputPolicy: `# METADATA
# title: "dummy title"
# description: "some description"
# scope: package
# schemas:
# - input: schema["dockerfile"]
# - input: schema["kubernetes"]
# custom:
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS1234
deny[res]{
	res := true
}`,
		},
		{
			name: "sad path schema does not exist",
			inputPolicy: `# METADATA
# title: "dummy title"
# description: "some description"
# scope: package
# schemas:
# - input: schema["invalid schema"]
# custom:
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS1234
deny[res]{
	res := true
}`,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policies, err := RecurseEmbeddedModules(rules.EmbeddedLibraryFileSystem, ".")
			require.NoError(t, err)
			mod, err := ast.ParseModuleWithOpts("/rules/newrule.rego", tc.inputPolicy, ast.ParserOptions{
				ProcessAnnotation: true,
			})
			require.NoError(t, err)

			policies["/rules/newrule.rego"] = mod
			switch {
			case tc.expectedError:
				assert.Panics(t, func() {
					RegisterRegoRules(policies)
				}, tc.name)
			default:
				RegisterRegoRules(policies)
			}
		})
	}
}
