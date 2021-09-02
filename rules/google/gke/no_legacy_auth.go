package gke

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoLegacyAuth = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "gke",
		ShortCode:   "no-legacy-auth",
		Summary:     "Clusters should use client certificates for authentication",
		Impact:      "Less secure authentication method in use",
		Resolution:  "Use client certificates for authentication",
		Explanation: `Client certificates are the most secure and recommended method of authentication.`,
		Links: []string{ 
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, x := range s.AWS.S3.Buckets {
			if x.Encryption.Enabled.IsFalse() {
				results.Add(
					"",
					x.Encryption.Enabled.Metadata(),
					x.Encryption.Enabled.Value(),
				)
			}
		}
		return
	},
)
