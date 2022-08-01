package cloudwatch

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudwatch"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var requireRootUserUsageAlarm = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0149",
		Provider:   providers.AWSProvider,
		Service:    "cloudwatch",
		ShortCode:  "require-root-user-usage-alarm",
		Summary:    "Ensure a log metric filter and alarm exist for usage of root user",
		Impact:     "The root user has significant permissions and should not be used for day to day tasks.",
		Resolution: "Create an alarm to alert on root user login",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_2: {
				"3.3",
			},
			framework.CIS_AWS_1_4: {
				"4.3",
			},
		},
		Explanation: ` You can do real-time monitoring of API calls directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.   
                                                                              
CIS recommends that you create a metric filter and alarm for root user login attempts. Monitoring for root user logins provides visibility into the use of a fully privileged account and an opportunity to reduce the use of it.`,
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
				if filter.FilterPattern.Contains(`$.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && &.eventType != "AwsServiceEvent"`, types.IgnoreWhitespace) {
					metricFilter = filter
					found = true
					break
				}
			}

			if !found {
				results.Add("Cloudtrail has no root user usage log filter", trail)
				continue
			}

			if metricAlarm := s.AWS.CloudWatch.GetAlarmByMetricName(metricFilter.FilterName.Value()); metricAlarm == nil {
				results.Add("Cloudtrail has no root user usage alarm", trail)
				continue
			}

			results.AddPassed(trail)
		}

		return
	},
)
