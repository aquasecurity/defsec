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

var requireRouteTableChangeAlarm = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0159",
		Provider:   providers.AWSProvider,
		Service:    "cloudwatch",
		ShortCode:  "require-network-gateway-changes-alarm",
		Summary:    "Ensure a log metric filter and alarm exist for route table changes",
		Impact:     "Route tables control the flow of network traffic, changes could be made to maliciously allow egress of data or external ingress. Without alerting, this could go unnoticed.",
		Resolution: "Create an alarm to alert on route table changes",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_2: {
				"3.13",
			},
			framework.CIS_AWS_1_4: {
				"4.13",
			},
		},
		Explanation: `You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.     
Routing tables route network traffic between subnets and to network gateways.                                                                   
                                                                              
CIS recommends that you create a metric filter and alarm for changes to route tables. Monitoring these changes helps ensure that all VPC traffic flows through an expected path.`,
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
				if filter.FilterPattern.Contains(`{($.eventName=CreateRoute) || 
					($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || 
					($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || 
					($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}`, types.IgnoreWhitespace) {
					metricFilter = filter
					found = true
					break
				}
			}

			if !found {
				results.Add("Cloudtrail has no route table change log filter", trail)
				continue
			}

			if metricAlarm := s.AWS.CloudWatch.GetAlarmByMetricName(metricFilter.FilterName.Value()); metricAlarm == nil {
				results.Add("Cloudtrail has no route table change alarm", trail)
				continue
			}

			results.AddPassed(trail)
		}

		return
	},
)
