package nas

import (
	"github.com/aquasecurity/defsec/internal/cidr"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicIngressNASSgr = rules.Register(
	scan.Rule{
		AVDID:       "AVD-NIF-0014",
		Aliases:     []string{"nifcloud-nas-no-public-ingress-nas-sgr"},
		Provider:    providers.NifcloudProvider,
		Service:     "nas",
		ShortCode:   "no-public-ingress-nas-sgr",
		Summary:     "An ingress nas security group rule allows traffic from /0.",
		Impact:      "Your port exposed to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links: []string{
			"https://pfs.nifcloud.com/api/nas/AuthorizeNASSecurityGroupIngress.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressNASSgrGoodExamples,
			BadExamples:         terraformNoPublicIngressNASSgrBadExamples,
			Links:               terraformNoPublicIngressNASSgrLinks,
			RemediationMarkdown: terraformNoPublicIngressNASSgrRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.Nifcloud.NAS.NASSecurityGroups {
			for _, rule := range group.CIDRs {
				if cidr.IsPublic(rule.Value()) && cidr.CountAddresses(rule.Value()) > 1 {
					results.Add(
						"NAS Security group rule allows ingress from public internet.",
						rule,
					)
				} else {
					results.AddPassed(&group)
				}
			}
		}
		return
	},
)
