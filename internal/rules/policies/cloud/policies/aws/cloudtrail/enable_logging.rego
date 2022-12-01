# METADATA
# title: "CloudTrail logging enabled"
# description: "Ensure logging is enabled for cloudtrail trail."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-getting-started.html
# custom:
#   avd_id: AVD-AWS-0201
#   provider: aws
#   service: cloudtrail
#   severity: MEDIUM
#   short_code: enable_logging
#   recommended_action: "Modify thr cloudtrail to enable logging"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0201

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
	not trail.islogging.value
	res := result.new("Trail is not logging enabled", trail.islogging)
}
