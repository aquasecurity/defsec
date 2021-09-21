package network

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicEgress = rules.Register(
	rules.Rule{
		Provider:    provider.KubernetesProvider,
		Service:     "network",
		ShortCode:   "no-public-egress",
		Summary:     "Public egress should not be allowed via network policies",
		Impact:      "Exfiltration of data to the public internet",
		Resolution:  "Remove public access except where explicitly required",
		Explanation: `You should not expose infrastructure to the public internet except where explicitly required`,
		Links: []string{ 
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled,
					
				)
			}
		}
		return
	},
)
