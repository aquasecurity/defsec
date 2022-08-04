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

var requireVPCChangeAlarm = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0160",
		Provider:   providers.AWSProvider,
		Service:    "cloudwatch",
		ShortCode:  "require-vpc-changes-alarm",
		Summary:    "Ensure a log metric filter and alarm exist for VPC changes",
		Impact:     "Route tables control the flow of network traffic, changes could be made to maliciously allow egress of data or external ingress. Without alerting, this could go unnoticed.",
		Resolution: "Create an alarm to alert on route table changes",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_2: {
				"3.14",
			},
			framework.CIS_AWS_1_4: {
				"4.14",
			},
		},
		Explanation: `You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.   
You can have more than one VPC in an account, and you can create a peer connection between two VPCs, enabling network traffic to route between VPCs.
                                                                              
CIS recommends that you create a metric filter and alarm for changes to VPCs. Monitoring these changes helps ensure that authentication and authorization controls remain intact.  `,
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
				if filter.FilterPattern.Contains(`{($.eventName=CreateVpc) || 
					($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || 
					($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || 
					($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || 
					($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || 
					($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}`, types.IgnoreWhitespace) {
					metricFilter = filter
					found = true
					break
				}
			}

			if !found {
				results.Add("Cloudtrail has no vpc change log filter", trail)
				continue
			}

			if metricAlarm := s.AWS.CloudWatch.GetAlarmByMetricName(metricFilter.FilterName.Value()); metricAlarm == nil {
				results.Add("Cloudtrail has no vpc change alarm", trail)
				continue
			}

			results.AddPassed(trail)
		}

		return
	},
)
