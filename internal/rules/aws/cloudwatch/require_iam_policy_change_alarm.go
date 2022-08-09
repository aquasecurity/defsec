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

var requireIAMPolicyChangeAlarm = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0150",
		Provider:   providers.AWSProvider,
		Service:    "cloudwatch",
		ShortCode:  "require-iam-policy-change-alarm",
		Summary:    "Ensure a log metric filter and alarm exist for IAM policy changes",
		Impact:     "IAM Policy changes could lead to excessive permissions and may have been performed maliciously.",
		Resolution: "Create an alarm to alert on IAM Policy changes",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_2: {
				"3.4",
			},
			framework.CIS_AWS_1_4: {
				"4.4",
			},
		},
		Explanation: `  You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.   
                                                                              
CIS recommends that you create a metric filter and alarm for changes made to IAM policies. Monitoring these changes helps ensure that authentication and authorization controls remain intact.`,
		Links: []string{
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html",
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
				if filter.FilterPattern.Contains(`{($.eventName=DeleteGroupPolicy) || 
($.eventName=DeleteRolePolicy) || 
($.eventName=DeleteUserPolicy) || 
($.eventName=PutGroupPolicy) || 
($.eventName=PutRolePolicy) || 
($.eventName=PutUserPolicy) || 
($.eventName=CreatePolicy) || 
($.eventName=DeletePolicy) || 
($.eventName=CreatePolicyVersion) || 
($.eventName=DeletePolicyVersion) || 
($.eventName=AttachRolePolicy) ||
($.eventName=DetachRolePolicy) ||
($.eventName=AttachUserPolicy) || 
($.eventName=DetachUserPolicy) || 
($.eventName=AttachGroupPolicy) || 
($.eventName=DetachGroupPolicy)}`, types.IgnoreWhitespace) {
					metricFilter = filter
					found = true
					break
				}
			}

			if !found {
				results.Add("Cloudtrail has no IAM policy change log filter", trail)
				continue
			}

			if metricAlarm := s.AWS.CloudWatch.GetAlarmByMetricName(metricFilter.FilterName.Value()); metricAlarm == nil {
				results.Add("Cloudtrail has no IAM Policy change alarm", trail)
				continue
			}

			results.AddPassed(trail)
		}

		return
	},
)
