package iam

import (
	"github.com/aquasecurity/defsec/pkg/framework"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/providers"
)

var checkNoUserAttachedPolicies = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0143",
		Provider:  providers.AWSProvider,
		Service:   "iam",
		ShortCode: "no-user-attached-policies",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_2: {"1.16"},
		},
		Summary:    "IAM policies should not be granted directly to users.",
		Impact:     "Complex access control is difficult to manage and maintain.",
		Resolution: "Grant policies at the group level instead.",
		Explanation: `
CIS recommends that you apply IAM policies directly to groups and roles but not users. Assigning privileges at the group or role level reduces the complexity of access management as the number of users grow. Reducing access management complexity might in turn reduce opportunity for a principal to inadvertently receive or retain excessive privileges.
			`,
		Links: []string{
			"https://console.aws.amazon.com/iam/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoUserAttachedPoliciesGoodExamples,
			BadExamples:         terraformNoUserAttachedPoliciesBadExamples,
			Links:               terraformNoUserAttachedPoliciesLinks,
			RemediationMarkdown: terraformNoUserAttachedPoliciesRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, user := range s.AWS.IAM.Users {
			if len(user.Policies) > 0 {
				results.Add("One or more policies are attached directly to a user", &user)
			} else {
				results.AddPassed(&user)
			}
		}
		return
	},
)
