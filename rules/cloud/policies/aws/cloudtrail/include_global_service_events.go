package cloudtrail

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var checkIncludeGlobalServiceEvents = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0344",
		Provider:    providers.AWSProvider,
		Service:     "cloudtrail",
		ShortCode:   "include-global-service-events",
		Summary:     "Specifies whether Cloudtrail is publishing events from global services such as IAM to the log files.		",
		Impact:      "Events from global services such as IAM are not being published to the log files",
		Resolution:  "Enable include global service events for Cloudtrail",
		Explanation: `Include Global Service Events is a default value for Cloudtrail and it publishes events from global services that are not region specific such as IAM, STS and CloudFront. It is feasible that a rogue actor compromising an AWS account might want to disable this field to remove trace of their actions.`,
		Links: []string{
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-global-service-events",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformIncludeGlobalServiceEventsGoodExamples,
			BadExamples:         terraformIncludeGlobalServiceEventsBadExamples,
			Links:               terraformIncludeGlobalServiceEventsLinks,
			RemediationMarkdown: terraformIncludeGlobalServiceEventsRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationIncludeGlobalServiceEventsGoodExamples,
			BadExamples:         cloudFormationIncludeGlobalServiceEventsBadExamples,
			Links:               cloudFormationIncludeGlobalServiceEventsLinks,
			RemediationMarkdown: cloudFormationIncludeGlobalServiceEventsRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, trail := range s.AWS.CloudTrail.Trails {
			if trail.IncludeGlobalServiceEvents.IsFalse() {
				results.Add(
					"Trail is not publishing events from global services such as IAM to the log files.",
					trail.IncludeGlobalServiceEvents,
				)
			} else {
				results.AddPassed(&trail)
			}
		}
		return
	},
)
