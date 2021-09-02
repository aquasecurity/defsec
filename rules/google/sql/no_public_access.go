package sql

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckNoPublicAccess = rules.Register(
	rules.Rule{
		Provider:    provider.GoogleProvider,
		Service:     "sql",
		ShortCode:   "no-public-access",
		Summary:     "Ensure that Cloud SQL Database Instances are not publicly exposed",
		Impact:      "Public exposure of sensitive data",
		Resolution:  "Remove public access from database instances",
		Explanation: `Database instances should be configured so that they are not available over the public internet, but to internal compute resources which access them.`,
		Links: []string{ 
			"https://www.cloudconformity.com/knowledge-base/gcp/CloudSQL/publicly-accessible-cloud-sql-instances.html",
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
