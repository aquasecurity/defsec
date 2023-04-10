package network

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var outdatedSSLPolicies = []string{
	"",
	"1",
	"Standard Ciphers A ver1",
	"2",
	"Standard Ciphers B ver1",
	"3",
	"Standard Ciphers C ver1",
	"5",
	"Ats Ciphers A ver1",
	"8",
	"Ats Ciphers D ver1",
}

var CheckUseSecureTlsPolicy = rules.Register(
	scan.Rule{
		AVDID:       "AVD-NIF-0020",
		Provider:    providers.NifcloudProvider,
		Service:     "network",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "An outdated SSL policy is in use by a load balancer.",
		Impact:      "The SSL policy is outdated and has known vulnerabilities",
		Resolution:  "Use a more recent TLS/SSL policy for the load balancer",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links: []string{
			"https://pfs.nifcloud.com/service/lb_l4.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, lb := range s.Nifcloud.Network.LoadBalancers {
			for _, listener := range lb.Listeners {
				for _, outdated := range outdatedSSLPolicies {
					if listener.TLSPolicy.EqualTo(outdated) && listener.Protocol.EqualTo("HTTPS") {
						results.Add(
							"Listener uses an outdated TLS policy.",
							listener.TLSPolicy,
						)
					} else {
						results.AddPassed(&listener)
					}
				}
			}
		}
		return
	},
)
