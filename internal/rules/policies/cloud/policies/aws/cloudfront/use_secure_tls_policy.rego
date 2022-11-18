# METADATA
# title: "Cloudfront Use Secure TLS Policy"
# description: "CloudFront distribution uses outdated SSL/TLS protocols."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html
# custom:
#   avd_id: AVD-AWS-0181
#   provider: aws
#   service: cloudfront
#   severity: HIGH
#   short_code: use-secure-tls-policy
#   recommended_action: "You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudfront.aws0181

deny[res] {
	dist := input.aws.cloudfront.distributions[_]
	dist.viewercertificate.minimumprotocolversion.value != "TLSv1.2_2021"
	res := result.new("Distribution allows unencrypted communications.", dist.viewercertificate.minimumprotocolversion)
}
