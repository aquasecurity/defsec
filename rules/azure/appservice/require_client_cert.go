package appservice

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckRequireClientCert = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "appservice",
		ShortCode:   "require-client-cert",
		Summary:     "Web App accepts incoming client certificate",
		Impact:      "Mutual TLS is not being used",
		Resolution:  "Enable incoming certificates for clients",
		Explanation: `The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled only an authenticated client with valid certificates can access the app.`,
		Links: []string{ 
		},
		Severity: severity.Low,
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
