# METADATA
# title: "CloudFront Enabled"
# description: "Ensure that AWS CloudFront service is used within your AWS account."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html
# custom:
#   avd_id: AVD-AWS-0314
#   provider: aws
#   service: cloudfront
#   severity: LOW
#   short_code: cloudfront_in_use
#   recommended_action: "Create CloudFront distributions as per requirement."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudfront.aws0314

deny[res] {
	count(input.aws.cloudfront.distributions) == 0
    res := sprintf("CloudFront service is not in use %v", [""])
}
