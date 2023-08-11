# METADATA
# title: "S3 Bucket Logging"
# description: "Ensures S3 bucket logging is enabled for S3 buckets.ff"
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - http://docs.aws.amazon.com/AmazonS3/latest/dev/Logging.html
# custom:
#   id: AVD-AWS-0089
#   avd_id: AVD-AWS-0089
#   provider: aws
#   service: s3
#   severity: LOW
#   short_code: enable-logging
#   recommended_action: "Enable bucket logging for each S3 bucket."
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: s3
#           provider: aws
package builtin.aws.s3.aws0089

deny[res] {
	bucket := input.aws.s3.buckets[_]
	not bucket.logging.enabled.value
	res := result.new("Bucket has logging disabled", bucket.logging.enabled)
}
