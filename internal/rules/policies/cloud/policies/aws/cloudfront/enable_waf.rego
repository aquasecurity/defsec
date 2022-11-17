# METADATA
# title: "CloudFront WAF Enabled"
# description: "Ensures CloudFront distributions have WAF enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service: cloudfront
#   severity: HIGH
#   short_code: enable-waf
#   recommended_action: "1. Enter the WAF service. 2. Enter Web ACLs and filter by global. 3. If no Web ACL is found, Create a new global Web ACL and in Resource type to associate with web ACL, select the Cloudfront Distribution."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudfront.aws0180

deny[res] {
	dist := input.aws.cloudfront.distributions[_]
	dist.wafid.value == ""
	res := result.new(" CloudFront distributions have WAF disabled", dist.wafid)
}
