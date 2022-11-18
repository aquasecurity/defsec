# METADATA
# title: "CloudTrail Encryption"
# description: "Ensures CloudTrail encryption at rest is enabled for logs"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: enable-at-rest-encryption
#   recommended_action: "Enable CloudTrail log encryption through the CloudTrail console or API"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0180

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
	trail.kmskeyid.value == ""
	res := result.new("Trail is not encrypted.",trail.kmskeyid)
}