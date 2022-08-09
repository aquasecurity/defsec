package ec2

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_AdaptVPC(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ec2.EC2
	}{
		{
			name: "defined",
			terraform: `
			resource "aws_default_vpc" "default" {
				tags = {
				  Name = "Default VPC"
				}
			  }

			  resource "aws_vpc" "main" {
				cidr_block = "4.5.6.7/32"
			  }

			resource "aws_security_group" "example" {
				name        = "http"
				description = "Allow inbound HTTP traffic"
			  
				ingress {
				  description = "Rule #1"
				  from_port   = 80
				  to_port     = 80
				  protocol    = "tcp"
				  cidr_blocks = [aws_vpc.main.cidr_block]
				}

				egress {
					cidr_blocks = ["1.2.3.4/32"]
				}
			  }

			resource "aws_network_acl_rule" "example" {
				egress         = false
				protocol       = "tcp"
				from_port      = 22
				to_port        = 22
				rule_action    = "allow"
				cidr_block     = "10.0.0.0/16"
			}

			resource "aws_security_group_rule" "example" {
				type              = "ingress"
				description = "Rule #2"
				security_group_id = aws_security_group.example.id
				from_port         = 22
				to_port           = 22
				protocol          = "tcp"
				cidr_blocks = [
				  "1.2.3.4/32",
				  "4.5.6.7/32",
				]
			  }
`,
			expected: ec2.EC2{
				DefaultVPCs: []ec2.DefaultVPC{
					{
						Metadata: types2.NewTestMetadata(),
					},
				},
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    types2.NewTestMetadata(),
						Description: types2.String("Allow inbound HTTP traffic", types2.NewTestMetadata()),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata: types2.NewTestMetadata(),

								Description: types2.String("Rule #1", types2.NewTestMetadata()),
								CIDRs: []types2.StringValue{
									types2.String("4.5.6.7/32", types2.NewTestMetadata()),
								},
							},
							{
								Metadata: types2.NewTestMetadata(),

								Description: types2.String("Rule #2", types2.NewTestMetadata()),
								CIDRs: []types2.StringValue{
									types2.String("1.2.3.4/32", types2.NewTestMetadata()),
									types2.String("4.5.6.7/32", types2.NewTestMetadata()),
								},
							},
						},

						EgressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    types2.NewTestMetadata(),
								Description: types2.String("", types2.NewTestMetadata()),
								CIDRs: []types2.StringValue{
									types2.String("1.2.3.4/32", types2.NewTestMetadata()),
								},
							},
						},
					},
				},
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: types2.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: types2.NewTestMetadata(),
								Type:     types2.String("ingress", types2.NewTestMetadata()),
								Action:   types2.String("allow", types2.NewTestMetadata()),
								Protocol: types2.String("tcp", types2.NewTestMetadata()),
								CIDRs: []types2.StringValue{
									types2.String("10.0.0.0/16", types2.NewTestMetadata()),
								},
							},
						},
						IsDefaultRule: types2.Bool(false, types2.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_security_group" "example" {
				ingress {
				}

				egress {
				}
			  }

			resource "aws_network_acl_rule" "example" {
			}
`,
			expected: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    types2.NewTestMetadata(),
						Description: types2.String("Managed by Terraform", types2.NewTestMetadata()),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    types2.NewTestMetadata(),
								Description: types2.String("", types2.NewTestMetadata()),
							},
						},

						EgressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    types2.NewTestMetadata(),
								Description: types2.String("", types2.NewTestMetadata()),
							},
						},
					},
				},
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: types2.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: types2.NewTestMetadata(),

								Type:     types2.String("ingress", types2.NewTestMetadata()),
								Action:   types2.String("", types2.NewTestMetadata()),
								Protocol: types2.String("-1", types2.NewTestMetadata()),
							},
						},
						IsDefaultRule: types2.Bool(false, types2.NewTestMetadata()),
					},
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

func TestVPCLines(t *testing.T) {
	src := `
	resource "aws_default_vpc" "default" {
	  }

	resource "aws_vpc" "main" {
		cidr_block = "4.5.6.7/32"
	  }

	resource "aws_security_group" "example" {
		name        = "http"
		description = "Allow inbound HTTP traffic"
	  
		ingress {
		  description = "HTTP from VPC"
		  from_port   = 80
		  to_port     = 80
		  protocol    = "tcp"
		  cidr_blocks = [aws_vpc.main.cidr_block]
		}

		egress {
			cidr_blocks = ["1.2.3.4/32"]
		}
	  }

	resource "aws_security_group_rule" "example" {
		type              = "ingress"
		security_group_id = aws_security_group.example.id
		from_port         = 22
		to_port           = 22
		protocol          = "tcp"
		cidr_blocks = [
		  "1.2.3.4/32",
		  "4.5.6.7/32",
		]
	  }
	  
	  resource "aws_network_acl_rule" "example" {
		egress         = false
		protocol       = "tcp"
		from_port      = 22
		to_port        = 22
		rule_action    = "allow"
		cidr_block     = "10.0.0.0/16"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.DefaultVPCs, 1)
	require.Len(t, adapted.SecurityGroups, 1)
	require.Len(t, adapted.NetworkACLs, 1)

	defaultVPC := adapted.DefaultVPCs[0]
	securityGroup := adapted.SecurityGroups[0]
	networkACL := adapted.NetworkACLs[0]

	assert.Equal(t, 2, defaultVPC.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, defaultVPC.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, securityGroup.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, securityGroup.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, securityGroup.Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, securityGroup.Description.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, securityGroup.IngressRules[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 19, securityGroup.IngressRules[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, securityGroup.IngressRules[0].Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, securityGroup.IngressRules[0].Description.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, securityGroup.IngressRules[0].CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, securityGroup.IngressRules[0].CIDRs[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, securityGroup.IngressRules[1].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 36, securityGroup.IngressRules[1].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 32, securityGroup.IngressRules[1].CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 35, securityGroup.IngressRules[1].CIDRs[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, securityGroup.EgressRules[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, securityGroup.EgressRules[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 22, securityGroup.EgressRules[0].CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, securityGroup.EgressRules[0].CIDRs[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, networkACL.Rules[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 45, networkACL.Rules[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 39, networkACL.Rules[0].Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 39, networkACL.Rules[0].Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 40, networkACL.Rules[0].Protocol.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 40, networkACL.Rules[0].Protocol.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 43, networkACL.Rules[0].Action.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 43, networkACL.Rules[0].Action.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 44, networkACL.Rules[0].CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 44, networkACL.Rules[0].CIDRs[0].GetMetadata().Range().GetEndLine())
}
