package apigateway

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	v1 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v1"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPublicAccess = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0004",
		Provider:    providers.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "no-public-access",
		Summary:     "No unauthorized access to API Gateway methods",
		Impact:      "API gateway methods can be accessed without authorization.",
		Resolution:  "Use and authorization method or require API Key",
		Explanation: `API Gateway methods should generally be protected by authorization or api key. OPTION verb calls can be used without authorization`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, api := range s.AWS.APIGateway.V1.APIs {
			if api.Metadata.IsUnmanaged() {
				continue
			}
			for _, resource := range api.Resources {
				for _, method := range resource.Methods {
					if method.HTTPMethod.EqualTo("OPTION") {
						continue
					}
					if method.APIKeyRequired.IsTrue() {
						continue
					}
					if method.AuthorizationType.EqualTo(v1.AuthorizationNone) {
						results.Add(
							"Authorization is not enabled for this method.",
							method.AuthorizationType,
						)
					} else {
						results.AddPassed(&method)
					}
				}
			}
		}
		return
	},
)
