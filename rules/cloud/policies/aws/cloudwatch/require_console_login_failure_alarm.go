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

var requireConsoleLoginFailureAlarm = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0152",
		Provider:   providers.AWSProvider,
		Service:    "cloudwatch",
		ShortCode:  "require-console-login-failures-alarm",
		Summary:    "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures",
		Impact:     "Failed attempts to log into the Management console may indicate an attempt to maliciously access an account. Failure to alert reduces visibility of this activity.",
		Resolution: "Create an alarm to alert on console login failures",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_2: {
				"3.6",
			},
			framework.CIS_AWS_1_4: {
				"4.6",
			},
		},
		Explanation: `You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.   
                                                                              
CIS recommends that you create a metric filter and alarm for failed console authentication attempts. Monitoring failed console logins might decrease lead time to detect an attempt to brute-force a credential, which might provide an indicator, such as source IP, that you can use in other event correlations.`,
		Links: []string{
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html",
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
				if filter.FilterPattern.Contains(`{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}`, types.IgnoreWhitespace) {
					metricFilter = filter
					found = true
					break
				}
			}

			if !found {
				results.Add("Cloudtrail has no console login failure log filter", trail)
				continue
			}

			if metricAlarm := s.AWS.CloudWatch.GetAlarmByMetricName(metricFilter.FilterName.Value()); metricAlarm == nil {
				results.Add("Cloudtrail has no console login failure alarm", trail)
				continue
			}

			results.AddPassed(trail)
		}

		return
	},
)
