# METADATA
# title: "S3 Bucket Logging"
# description: "Ensures S3 bucket logging is enabled for S3 buckets"
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html
# custom:
#   id: AVD-AWS-0089
#   avd_id: AVD-AWS-0089
#   provider: aws
#   service: s3
#   severity: LOW
#   short_code: enable-logging
#   recommended_action: "Add a logging block to the resource to enable access logging"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: s3
#           provider: aws
#   terraform:
#       good_examples: "rules/cloud/policies/aws/s3/enable_bucket_logging.tf.go"
#       links: "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket"
#   cloud_formation:
#       good_examples: "rules/cloud/policies/aws/s3/enable_bucket_logging.cf.go"
package builtin.aws.s3.aws0089

deny[res] {
	bucket := input.aws.s3.buckets[_]
	not bucket.acl.value == "log-delivery-write"
	not bucket.logging.enabled.value
	res := result.new("Bucket has logging disabled", bucket.logging.enabled)
}
