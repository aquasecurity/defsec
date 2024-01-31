# METADATA
# title: "S3 Bucket Versioning"
# description: "Ensures object versioning is enabled on S3 buckets"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html
# custom:
#   avd_id: AVD-AWS-0216
#   provider: aws
#   service: s3
#   severity: MEDUIM
#   short_code: enable-versioning
#   recommended_action: "Versioning in Amazon S3 is a means of keeping multiple variants of an object in the same bucket. 
#                        You can use the S3 Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. 
#                        With versioning you can recover more easily from both unintended user actions and application failures."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.s3.aws0216

deny[res] {
	bucket := input.aws.s3.buckets[_]
	not bucket.versioning.enabled.value
	res := result.new("Bucket does not have versioning enabled", bucket.versioning.enabled)
}
