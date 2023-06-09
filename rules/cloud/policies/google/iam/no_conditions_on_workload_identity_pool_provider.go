package iam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoConditionOnWorkloadIdentityPoolProvider = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0068",
		Provider:    providers.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-conditions-workload-identity-pool-provider",
		Summary:     "A configuration for an external workload identity pool provider should have conditions set",
		Impact:      "Allows an external attacker to authenticate as the attached service account and act with its permissions",
		Resolution:  "Set conditions on this provider, for example by restricting it to only be allowed from repositories in your GitHub organization",
		Explanation: `In GitHub Actions, one can authenticate to Google Cloud by setting values for workload_identity_provider and service_account and requesting a short-lived OIDC token which is then used to execute commands as that Service Account. If you don't specify a condition in the workload identity provider pool configuration, then any GitHub Action can assume this role and act as that Service Account.`,
		Links: []string{
			"https://www.revblock.dev/exploiting-misconfigured-google-cloud-service-accounts-from-github-actions/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoConditionOnWorkloadIdentityPoolProviderGoodExamples,
			BadExamples:         terraformNoConditionOnWorkloadIdentityPoolProviderBadExamples,
			Links:               terraformNoConditionOnWorkloadIdentityPoolProviderLinks,
			RemediationMarkdown: terraformNoConditionOnWorkloadIdentityPoolProviderMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, provider := range s.Google.IAM.WorkloadIdentityPoolProviders {
			if provider.AttributeCondition.IsEmpty() {
				results.Add(
					"Project has automatic network creation enabled.",
					provider.AttributeCondition,
				)
			} else {
				results.AddPassed(provider)
			}
		}
		return
	},
)
