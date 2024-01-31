# METADATA
# title: "CloudWatch log-group-customer-key encrypted"
# description: "Ensures CloudWatch log groups should be encrypted using CMK."
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html
# custom:
#   avd_id: AVD-AWS-0181
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   short_code: log-group-customer-key
#   recommended_action: "CloudWatch log groups are encrypted by default, however, to get the full benefit of controlling key rotation and other KMS aspects a KMS CMK should be used."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudwatch.aws0181

deny[res] {
	group := input.aws.cloudwatch.loggroups[_]
	group.kmskeyid.value == ""
	res := result.new("Log group is not encrypted", group.kmskeyid)
}
