#METADATA
# title: "CloudTrail Log Validation"
# description: "Cloudtrail log validation should be enabled to prevent tampering of log data"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
# custom:
#   avd_id: AVD-AWS-0181
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: enable-log-validation
#   recommended_action: "Log validation should be activated on Cloudtrail logs to prevent the tampering of the underlying data in the S3 bucket. It is feasible that a rogue actor compromising an AWS account might want to modify the log data to remove trace of their actions."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0181

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
	not trail.enablelogfilevalidation.value
	res := result.new("Trail does not have log validation enabled.", trail.enablelogfilevalidation)
}
