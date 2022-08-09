package iam

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/liamg/iamgo"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptUsers(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []iam.User
	}{
		{
			name: "basic",
			terraform: `
			resource "aws_iam_user" "lb" {
				name = "loadbalancer"
				path = "/system/"
			  }
			  
			resource "aws_iam_user_policy" "policy" {
				name = "test"
				user = aws_iam_user.lb.name
	

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
			expected: []iam.User{
				{
					Metadata:   types2.NewTestMetadata(),
					Name:       types2.String("loadbalancer", types2.NewTestMetadata()),
					LastAccess: types2.TimeUnresolvable(types2.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: types2.NewTestMetadata(),
							Name:     types2.String("test", types2.NewTestMetadata()),
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
									Metadata: types2.NewTestMetadata(),
									IsOffset: false,
									HasRefs:  false,
								}
							}(),
							Builtin: types2.Bool(false, types2.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptUsers(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
