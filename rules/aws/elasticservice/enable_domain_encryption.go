package elasticservice

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableDomainEncryption = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "elastic-service",
		ShortCode:   "enable-domain-encryption",
		Summary:     "Elasticsearch domain isn't encrypted at rest.",
		Impact:      "Data will be readable if compromised",
		Resolution:  "Enable ElasticSearch domain encryption",
		Explanation: `You should ensure your Elasticsearch data is encrypted at rest to help prevent sensitive information from being read by unauthorised users.`,
		Links: []string{ 
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html",
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
