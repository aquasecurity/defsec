package networking

import (
	"github.com/aquasecurity/defsec/cidr"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicAccessSecurityGroup = rules.Register(
	rules.Rule{
		AVDID:       "AVD-OPNSTK-0003",
		Provider:    provider.OpenStackProvider,
		Service:     "network",
		ShortCode:   "no-public-access-sg",
		Summary:     "A Security Group rule allows traffic from the public internet",
		Impact:      "Exposure of infrastructure to the public internet",
		Resolution:  "Employ more restrictive Security Group rules",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links:       []string{},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessSGGoodExamples,
			BadExamples:         terraformNoPublicAccessSGBadExamples,
			Links:               terraformNoPublicAccessSGLinks,
			RemediationMarkdown: terraformNoPublicAccessSGRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		if s.OpenStack.Networking.IsUnmanaged() {
			return
		}

		if s.OpenStack.Networking.IsIngress() && cidr.IsPublic(s.OpenStack.Networking.RemoteIPPrefix.Value()) {
			results.Add(
				"Security Group allows public ingress",
				s.OpenStack.Networking.RemoteIPPrefix,
			)
		} else {
			results.AddPassed(s.OpenStack.Networking)
		}
		return
	},
)
