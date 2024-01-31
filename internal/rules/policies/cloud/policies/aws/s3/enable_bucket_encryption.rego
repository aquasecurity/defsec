# METADATA
# title: "S3 Bucket Encryption"
# description: "Ensures object encryption is enabled on S3 buckets"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html
# custom:
#   avd_id: AVD-AWS-0215
#   provider: aws
#   service: s3
#   severity: HIGH
#   short_code: enable-bucket-encryption
#   recommended_action: "Enable CMK KMS-based encryption for all S3 buckets."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.s3.aws0215

deny[res] {
	bucket := input.aws.s3.buckets[_]
	not bucket.encryption.enabled.value
	res := result.new("Bucket does not have encryption enabled", bucket.encryption.enabled)
}
