package vpc

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoExcessivePortAccess = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "vpc",
		ShortCode:   "no-excessive-port-access",
		Summary:     "An ingress Network ACL rule allows ALL ports.",
		Impact:      "All ports exposed for egressing data",
		Resolution:  "Set specific allowed ports",
		Explanation: `Ensure access to specific required ports is allowed, and nothing else.`,
		Links: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, acl := range s.AWS.VPC.NetworkACLRules {
			if acl.Protocol.EqualTo("all") || acl.Protocol.EqualTo("-1") {
				results.Add(
					"Network ACL rule allows access using ALL ports.",
					acl.Protocol,
				)
			}
		}
		return
	},
)
