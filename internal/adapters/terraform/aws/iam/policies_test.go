package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/liamg/iamgo"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptPolicies(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []iam.Policy
	}{
		{
			name: "basic",
			terraform: `
			resource "aws_iam_policy" "policy" {
				name = "test"	

				policy = jsonencode({
					Version = "2012-10-17"
					Statement = [
					  {
						Action = [
						  "ec2:Describe*",
						]
						Effect   = "Allow"
						Resource = "*"
					  },
					]
				  })
			  }
`,
			expected: []iam.Policy{
				{
					Metadata: types.NewTestMetadata(),
					Name:     types.String("test", types.NewTestMetadata()),
					Document: func() iam.Document {

						builder := iamgo.NewPolicyBuilder()
						builder.WithVersion("2012-10-17")

						sb := iamgo.NewStatementBuilder()

						sb.WithEffect(iamgo.EffectAllow)
						sb.WithActions([]string{"ec2:Describe*"})
						sb.WithResources([]string{"*"})

						builder.WithStatement(sb.Build())

						return iam.Document{
							Parsed:   builder.Build(),
							Metadata: types.NewTestMetadata(),
							IsOffset: false,
							HasRefs:  false,
						}
					}(),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptPolicies(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
