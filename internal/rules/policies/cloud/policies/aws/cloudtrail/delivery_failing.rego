# METADATA
# title: "CloudTrail Delivery Failing"
# description: "Ensures that Amazon CloudTrail trail log files are delivered to destination S3 bucket."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-cloudtrail-works.html
# custom:
#   avd_id: AVD-AWS-0328
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: delivery_failing
#   recommended_action: "Modify CloudTrail trail configurations so that logs are being delivered."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0328

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
    trail.latestdeliveryerror
	res := result.new("Logs for CloudTrail trail are not being delivered", trail)
}
