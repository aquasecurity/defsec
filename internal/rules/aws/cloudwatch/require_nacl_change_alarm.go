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

var requireNACLChangeAlarm = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0157",
		Provider:   providers.AWSProvider,
		Service:    "cloudwatch",
		ShortCode:  "require-nacl-changes-alarm",
		Summary:    "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)",
		Impact:     "Network ACLs control the ingress and egress, changes could be made to maliciously allow egress of data or external ingress. Without alerting, this could go unnoticed.",
		Resolution: "Create an alarm to alert on network acl changes",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_2: {
				"3.11",
			},
			framework.CIS_AWS_1_4: {
				"4.11",
			},
		},
		Explanation: `You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.   
NACLs are used as a stateless packet filter to control ingress and egress traffic for subnets in a VPC.                                               
                                                                              
CIS recommends that you create a metric filter and alarm for changes to NACLs. Monitoring these changes helps ensure that AWS resources and services aren't unintentionally exposed.`,
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
				if filter.FilterPattern.Contains(`{($.eventName=CreateNetworkAcl) || 
					($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || 
					($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || 
					($.eventName=ReplaceNetworkAclAssociation)}`, types.IgnoreWhitespace) {
					metricFilter = filter
					found = true
					break
				}
			}

			if !found {
				results.Add("Cloudtrail has no network ACL change log filter", trail)
				continue
			}

			if metricAlarm := s.AWS.CloudWatch.GetAlarmByMetricName(metricFilter.FilterName.Value()); metricAlarm == nil {
				results.Add("Cloudtrail has no network ACL change alarm", trail)
				continue
			}

			results.AddPassed(trail)
		}

		return
	},
)
