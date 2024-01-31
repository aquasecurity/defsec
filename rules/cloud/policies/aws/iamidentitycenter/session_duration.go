package iamidentitycenter

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckSessionDuration = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0346",
		Provider:    providers.AWSProvider,
		Service:     "iamidentitycenter",
		ShortCode:   "session-duration",
		Summary:     "User session duration should be defined",
		Impact:      "Extended user initiated sessions allow opportunity for misuse",
		Resolution:  "Set session duration following ISO-8601 standard",
		Explanation: "Session termination addresses the termination of user-initiated logical sessions.",
		Links: []string{
			"https://docs.aws.amazon.com/singlesignon/latest/userguide/howtosessionduration.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformSessionDurationGoodExamples,
			BadExamples:         terraformSessionDurationBadExamples,
			Links:               terraformSessionDurationLinks,
			RemediationMarkdown: terraformSessionDurationRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationSessionDurationGoodExamples,
			BadExamples:         cloudFormationSessionDurationBadExamples,
			Links:               cloudFormationSessionDurationLinks,
			RemediationMarkdown: cloudFormationSessionDurationRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, permissionset := range s.AWS.IAMIdentityCenter.PermissionSets {
			if permissionset.SessionDuration.IsEmpty() {
				results.Add(
					"Permission set does not have session duration set.",
					permissionset.SessionDuration,
				)
			} else {
				results.AddPassed(&permissionset)
			}
		}
		return
	},
)
