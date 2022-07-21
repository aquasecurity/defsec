package ec2

import (
	"github.com/aquasecurity/defsec/internal/cidr"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicIngress = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0105",
		Aliases:     []string{"aws-vpc-no-public-ingress-acl"},
		Provider:    providers.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-public-ingress-acl",
		Summary:     "An ingress Network ACL rule allows specific ports from /0.",
		Impact:      "The ports are exposed for ingressing data to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressAclGoodExamples,
			BadExamples:         terraformNoPublicIngressAclBadExamples,
			Links:               terraformNoPublicIngressAclLinks,
			RemediationMarkdown: terraformNoPublicIngressAclRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicIngressAclGoodExamples,
			BadExamples:         cloudFormationNoPublicIngressAclBadExamples,
			Links:               cloudFormationNoPublicIngressAclLinks,
			RemediationMarkdown: cloudFormationNoPublicIngressAclRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, acl := range s.AWS.EC2.NetworkACLs {
			for _, rule := range acl.Rules {
				if !rule.Type.EqualTo(ec2.TypeIngress) {
					continue
				}
				if !rule.Action.EqualTo(ec2.ActionAllow) {
					continue
				}
				var fail bool
				for _, block := range rule.CIDRs {
					if cidr.IsPublic(block.Value()) && cidr.CountAddresses(block.Value()) > 1 {
						fail = true
						results.Add(
							"Network ACL rule allows ingress from public internet.",
							block,
						)
					}
				}
				if !fail {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
