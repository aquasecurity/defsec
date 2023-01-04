# METADATA
# title: "CloudTrail Notifications Enabled"
# description: "Ensure that Amazon CloudTrail trails are using active Simple Notification Service (SNS) topics to deliver notifications."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html
# custom:
#   avd_id: AVD-AWS-0325
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: management_events
#   recommended_action: "Make sure that CloudTrail trails are using active SNS topics and that SNS topics have not been deleted after trail creation."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0325

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
    trail.snstopicname
	topic := input.aws.sns.topics[_]
	trail.snstopicname.value != topic.arn.value
	res := result.new("CloudTrail trail SNS topic not found", trail)
}
