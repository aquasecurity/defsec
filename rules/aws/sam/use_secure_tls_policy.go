package sam

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0112",
		Provider:    provider.AWSProvider,
		Service:     "sam",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "SAM API domain name uses outdated SSL/TLS protocols.",
		Impact:      "Outdated SSL policies increase exposure to known vulnerabilities",
		Resolution:  "Use the most modern TLS/SSL policies available",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links: []string{
			"https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, api := range s.AWS.SAM.APIs {
			if api.DomainConfiguration.SecurityPolicy.NotEqualTo("TLS_1_2") {
				results.Add(
					"Domain name is configured with an outdated TLS policy.",
					&api,
					api.DomainConfiguration.SecurityPolicy,
				)
			} else {
				results.AddPassed(&api)
			}
		}
		return
	},
)
