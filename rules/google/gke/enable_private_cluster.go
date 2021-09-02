package gke

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnablePrivateCluster = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-private-cluster",
		Summary:     "Clusters should be set to private",
		Impact:      "Nodes may be exposed to the public internet",
		Resolution:  "Enable private cluster",
		Explanation: `Enabling private nodes on a cluster ensures the nodes are only available internally as they will only be assigned internal addresses.`,
		Links: []string{ 
		},
		Severity: severity.Medium,
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
