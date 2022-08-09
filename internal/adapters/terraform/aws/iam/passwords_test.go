package iam

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptPasswordPolicy(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  iam.PasswordPolicy
	}{
		{
			name: "basic",
			terraform: `
			resource "aws_iam_account_password_policy" "strict" {
				minimum_password_length        = 8
				require_lowercase_characters   = true
				require_numbers                = true
				require_uppercase_characters   = true
				require_symbols                = true
				allow_users_to_change_password = true
				max_password_age               = 90
				password_reuse_prevention      = 3
			  }
`,
			expected: iam.PasswordPolicy{
				Metadata:             types2.NewTestMetadata(),
				ReusePreventionCount: types2.Int(3, types2.NewTestMetadata()),
				RequireLowercase:     types2.Bool(true, types2.NewTestMetadata()),
				RequireUppercase:     types2.Bool(true, types2.NewTestMetadata()),
				RequireNumbers:       types2.Bool(true, types2.NewTestMetadata()),
				RequireSymbols:       types2.Bool(true, types2.NewTestMetadata()),
				MaxAgeDays:           types2.Int(90, types2.NewTestMetadata()),
				MinimumLength:        types2.Int(8, types2.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptPasswordPolicy(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
