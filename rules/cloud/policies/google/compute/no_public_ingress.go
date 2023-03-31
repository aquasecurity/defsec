package compute

import (
	"github.com/aquasecurity/defsec/internal/cidr"
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicIngress = rules.Register(
	scan.Rule{
		AVDID:      "AVD-GCP-0027",
		Provider:   providers.GoogleProvider,
		Service:    "compute",
		ShortCode:  "no-public-ingress",
		Summary:    "An inbound firewall rule allows traffic from /0.",
		Impact:     "The port is exposed for ingress from the internet",
		Resolution: "Set a more restrictive cidr range",
		Explanation: `Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.`,
		Links: []string{
			"https://cloud.google.com/vpc/docs/using-firewalls",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressGoodExamples,
			BadExamples:         terraformNoPublicIngressBadExamples,
			Links:               terraformNoPublicIngressLinks,
			RemediationMarkdown: terraformNoPublicIngressRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, network := range s.Google.Compute.Networks {
			if network.Firewall == nil {
				continue
			}

			if len(network.Firewall.SourceTags) > 0 && len(network.Firewall.TargetTags) > 0 {
				continue
			}

			for _, rule := range network.Firewall.IngressRules {
				if !rule.IsAllow.IsTrue() {
					continue
				}
				if rule.Enforced.IsFalse() {
					continue
				}
				for _, source := range rule.SourceRanges {
					if cidr.IsPublic(source.Value()) && cidr.CountAddresses(source.Value()) > 1 {
						results.Add(
							"Firewall rule allows ingress traffic from multiple addresses on the public internet.",
							source,
						)
					} else {
						results.AddPassed(source)
					}
				}
			}
		}
		return
	},
)
