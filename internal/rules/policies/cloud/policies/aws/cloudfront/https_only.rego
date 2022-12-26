# METADATA
# title: "CloudFront HTTPS Only"
# description: "Ensures CloudFront distributions are configured to redirect non-HTTPS traffic to HTTPS."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/CloudFront.html
# custom:
#   avd_id: AVD-AWS-0313
#   provider: aws
#   service: cloudfront
#   severity: CRITICAL
#   short_code: https_only
#   recommended_action: "Remove HTTP-only listeners from distributions."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudfront.aws0313

deny[res] {
	distribution := input.aws.cloudfront.distributions[_]
	all([distribution.defaultcachebehaviour.viewerprotocolpolicy.value != "redirect-to-https",
         distribution.defaultcachebehaviour.viewerprotocolpolicy.value != "https-only"])
	res := result.new("CloudFront distribution is not configured to use HTTPS", distribution.defaultcachebehaviour.viewerprotocolpolicy)
}
