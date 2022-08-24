package cloudwatch

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
)

var requireNonMFALoginAlarm = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0148",
		Provider:   providers.AWSProvider,
		Service:    "cloudwatch",
		ShortCode:  "require-non-mfa-login-alarm",
		Summary:    "Ensure a log metric filter and alarm exist for AWS Management Console sign-in without MFA",
		Impact:     "Not alerting on logins with no MFA allows the risk to go un-notified.",
		Resolution: "Create an alarm to alert on non MFA logins",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_2: {
				"3.2",
			},
			framework.CIS_AWS_1_4: {
				"4.2",
			},
		},
		Explanation: `You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.   
                                                                              
  CIS recommends that you create a metric filter and alarm console logins that  aren't protected by MFA. Monitoring for single-factor console logins increases visibility into accounts that aren't protected by MFA.`,
		Links: []string{
			"https://aws.amazon.com/iam/features/mfa/",
		},
		Terraform:      &scan.EngineMetadata{},
		CloudFormation: &scan.EngineMetadata{},
		Severity:       severity.Low,
	},
	func(s *state.State) (results scan.Results) {

		multiRegionTrails := s.AWS.CloudTrail.MultiRegionTrails()
		for _, trail := range multiRegionTrails {
			logGroup := s.AWS.CloudWatch.GetLogGroupByArn(trail.CloudWatchLogsLogGroupArn.Value())
			if logGroup == nil || trail.IsLogging.IsFalse() {
				continue
			}

			var metricFilter cloudwatch.MetricFilter
			var found bool
			for _, filter := range logGroup.MetricFilters {
				if filter.FilterPattern.Contains(`($.eventName = "ConsoleLogin") && 
($.additionalEventData.MFAUsed != "Yes") && 
($.userIdentity.type=="IAMUser") && 
($.responseElements.ConsoleLogin == "Success")`, types.IgnoreWhitespace) {
					metricFilter = filter
					found = true
					break
				}
			}

			if !found {
				results.Add("Cloudtrail has no non-MFA login log filter", trail)
				continue
			}

			if metricAlarm := s.AWS.CloudWatch.GetAlarmByMetricName(metricFilter.FilterName.Value()); metricAlarm == nil {
				results.Add("Cloudtrail has no non-MFA login alarm", trail)
				continue
			}

			results.AddPassed(trail)
		}

		return
	},
)
