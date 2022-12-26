# METADATA
# title: "CloudFront Compress Objects Automatically'"
# description: "Ensure that your Amazon Cloudfront distributions are configured to automatically compress files(object)."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html
# custom:
#   avd_id: AVD-AWS-0316
#   provider: aws
#   service: cloudfront
#   severity: LOW
#   short_code: compress_object_automatically
#   recommended_action: "Ensures that CloudFront is configured to automatically compress files"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudfront.aws0316

deny[res] {
    distribution := input.aws.cloudfront.distributions[_]
    distribution.defaultcachebehaviour.compress.value == false
    res := result.new("'CloudFront distribution is not configured to compress files automatically", distribution.defaultcachebehaviour.compress)
}