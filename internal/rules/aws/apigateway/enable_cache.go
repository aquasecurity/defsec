package apigateway

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableCache = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0179",
		Provider:   providers.AWSProvider,
		Service:    "api-gateway",
		ShortCode:  "enable-cache",
		Summary:    "Ensure that response caching is enabled for your Amazon API Gateway REST APIs.",
		Impact:     "",
		Resolution: "Enable cache",
		Explanation: "A REST API in API Gateway is a collection of resources and methods that are integrated with backend HTTP endpoints, Lambda functions, or other AWS services.You can enable API caching in Amazon API Gateway to cache your endpoint responses." +
			"With caching, you can reduce the number of calls made to your endpoint and also improve the latency of requests to your API.",
		Links: []string{"https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html"},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableCacheGoodExamples,
			BadExamples:         terraformEnableCacheBadExamples,
			Links:               terraformEnableCacheLinks,
			RemediationMarkdown: terraformEnableCacheRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, api := range s.AWS.APIGateway.V1.APIs {
			if api.Metadata.IsUnmanaged() {
				continue
			}
			for _, stage := range api.Stages {
				if stage.Metadata.IsUnmanaged() {
					continue
				}
				for _, settings := range stage.RESTMethodSettings {
					if settings.Metadata.IsUnmanaged() {
						continue
					}
					if settings.CacheEnabled.IsFalse() {
						results.Add(
							"Cache data is not enabled.",
							settings.CacheEnabled,
						)
					} else {
						results.AddPassed(&settings)
					}

				}
			}
		}
		return
	},
)
