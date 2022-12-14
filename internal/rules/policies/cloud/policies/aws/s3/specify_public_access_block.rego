# METADATA
# title: "S3 Bucket Public Access Block"
# description: "Ensures S3 public access block is enabled on all buckets or for AWS account"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
# custom:
#   avd_id: AVD-AWS-0218
#   provider: aws
#   service: s3
#   severity: LOW
#   short_code: specify-public-access-block
#   recommended_action: "Enable the S3 public access block on all S3 buckets or for AWS account."
#   input:
#     selector:
#     - type: cloud
 package builtin.aws.s3.aws0218
 import future.keywords.in

deny[res] {
	bucket := input.aws.s3.buckets[_]
    not bucket.publicaccessblock
	res := result.new("Bucket does not have a corresponding public access block", bucket)
}
{
 	bucket := input.aws.s3.buckets[_]
	string := [ keys |
		some key, val in bucket.publicaccessblock
		val.value == false
		keys:= key
	]
	count(string) > 0
	output := concat(",", string)
	res := result.new(sprintf("S3 bucket is missing public access blocks: %v",[output]), bucket.publicaccessblock)
}
