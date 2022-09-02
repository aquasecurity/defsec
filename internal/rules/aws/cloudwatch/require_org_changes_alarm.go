package cloudwatch

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
)

var CheckRequireOrgChangesAlarm = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0174",
		Provider:   providers.AWSProvider,
		Service:    "cloudwatch",
		ShortCode:  "require-org-changes-alarm",
		Summary:    "Ensure a log metric filter and alarm exist for organisation changes",
		Impact:     "Lack of observability into critical organisation changes",
		Resolution: "Create an alarm to alert on organisation changes",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {
				"4.15",
			},
		},
		Explanation: `
Monitoring AWS Organizations changes can help you prevent any unwanted, accidental or
intentional modifications that may lead to unauthorized access or other security breaches.
This monitoring technique helps you to ensure that any unexpected changes performed
within your AWS Organizations can be investigated and any unwanted changes can be
rolled back.
`,
		Links: []string{
			"https://docs.aws.amazon.com/organizations/latest/userguide/orgs_security_incident-response.html",
		},
		Terraform:      &scan.EngineMetadata{},
		CloudFormation: &scan.EngineMetadata{},
		Severity:       severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		if metricAlarm := s.AWS.CloudWatch.GetAlarmByMetricName("OrganizationEvents"); metricAlarm == nil {
			results.Add("CloudWatch has no alarm associated with organisation events", types.NewUnmanagedMetadata())
		} else {
			results.AddPassed(metricAlarm)
		}
		return
	},
)
