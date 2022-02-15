package secrets

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"

	"github.com/aquasecurity/defsec/provider/github"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []github.EnvironmentSecret
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []github.EnvironmentSecret{},
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

func Test_adaptSecrets(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  []github.EnvironmentSecret
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: []github.EnvironmentSecret{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptSecrets(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSecret(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  github.EnvironmentSecret
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: github.EnvironmentSecret{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptSecret(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
