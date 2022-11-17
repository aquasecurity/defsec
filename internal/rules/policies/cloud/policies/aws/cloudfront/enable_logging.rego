# METADATA
# title: "CloudFront Logging Enabled"
# description: "Ensures CloudFront distributions have request logging enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html
# custom:
#   avd_id: AVD-AWS-0179
#   provider: aws
#   service: cloudfront
#   severity: MEDIUM
#   short_code: enable-logging
#   recommended_action: "Enable CloudFront request logging."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudfront.aws0179

deny[res] {
	dist := input.aws.cloudfront.distributions[_]
	dist.logging.bucket.value == ""
	res := result.new("Distribution request logging not enabled", dist.logging.bucket)
}
