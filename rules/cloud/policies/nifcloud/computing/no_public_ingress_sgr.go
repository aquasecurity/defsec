package computing

import (
	"github.com/aquasecurity/defsec/internal/cidr"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicIngressSgr = rules.Register(
	scan.Rule{
		AVDID:      "AVD-NIF-0001",
		Aliases:    []string{"nifcloud-computing-no-public-ingress-sgr"},
		Provider:   providers.NifcloudProvider,
		Service:    "computing",
		ShortCode:  "no-public-ingress-sgr",
		Summary:    "An ingress security group rule allows traffic from /0.",
		Impact:     "Your port exposed to the internet",
		Resolution: "Set a more restrictive cidr range",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
When publishing web applications, use a load balancer instead of publishing directly to instances.
		`,
		Links: []string{
			"https://pfs.nifcloud.com/help/fw/rule_new.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressSgrGoodExamples,
			BadExamples:         terraformNoPublicIngressSgrBadExamples,
			Links:               terraformNoPublicIngressSgrLinks,
			RemediationMarkdown: terraformNoPublicIngressSgrRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.Nifcloud.Computing.SecurityGroups {
			for _, rule := range group.IngressRules {
				if cidr.IsPublic(rule.CIDR.Value()) && cidr.CountAddresses(rule.CIDR.Value()) > 1 {
					results.Add(
						"Security group rule allows ingress from public internet.",
						rule.CIDR,
					)
				} else {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
