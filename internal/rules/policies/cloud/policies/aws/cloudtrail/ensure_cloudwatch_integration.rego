# METADATA
# title: "CloudTrail To CloudWatch"
# description: "Ensures CloudTrail logs are being properly delivered to CloudWatch"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html#send-cloudtrail-events-to-cloudwatch-logs-console
# custom:
#   avd_id: AVD-AWS-0182
#   provider: aws
#   service: cloudtrail
#   severity: LOW
#   short_code: ensure-cloudwatch-integration
#   recommended_action: "Enable CloudTrail CloudWatch integration for all regions"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0182

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
	trail.cloudwatchlogsloggrouparn.value == ""
	res := result.new("Trail does not have CloudWatch logging configured", trail.cloudwatchlogsloggrouparn)
}
