package ec2

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckRequireVPCFlowLogs = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0178",
		Aliases:     []string{"aws-autoscaling-enable-at-rest-encryption"},
		Provider:    providers.AWSProvider,
		Service:     "ec2",
		ShortCode:   "require-vpc-flow-logs-for-all-vpcs",
		Summary:     `VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet "Rejects" for VPCs.`,
		Impact:      "Without VPC flow logs, you risk not having enough information about network traffic flow to investigate incidents or identify security issues.",
		Resolution:  "Enable flow logs for VPC",
		Explanation: `VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or insight during security workflows.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html",
		},
		Terraform:      &scan.EngineMetadata{},
		CloudFormation: &scan.EngineMetadata{},
		Severity:       severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, vpc := range s.AWS.EC2.VPCs {
			if vpc.FlowLogsEnabled.IsFalse() {
				results.Add("VPC Flow Logs is not enabled for VPC "+vpc.ID.Value(), vpc)
			} else {
				results.AddPassed(vpc)
			}
		}
		return
	},
)
