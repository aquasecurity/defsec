package iam

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckNoPasswordReuse = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0056",
		Provider:  providers.AWSProvider,
		Service:   "iam",
		ShortCode: "no-password-reuse",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_2: {"1.10"},
			framework.CIS_AWS_1_4: {"1.9"},
		},
		Summary:    "IAM Password policy should prevent password reuse.",
		Impact:     "Password reuse increase the risk of compromised passwords being abused",
		Resolution: "Prevent password reuse in the policy",
		Explanation: `IAM account password policies should prevent the reuse of passwords. 

The account password policy should be set to prevent using any of the last five used passwords.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPasswordReuseGoodExamples,
			BadExamples:         terraformNoPasswordReuseBadExamples,
			Links:               terraformNoPasswordReuseLinks,
			RemediationMarkdown: terraformNoPasswordReuseRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {

		policy := s.AWS.IAM.PasswordPolicy
		if policy.IsUnmanaged() {
			return
		}

		if policy.ReusePreventionCount.LessThan(5) {
			results.Add(
				"Password policy allows reuse of recent passwords.",
				policy.ReusePreventionCount,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)
