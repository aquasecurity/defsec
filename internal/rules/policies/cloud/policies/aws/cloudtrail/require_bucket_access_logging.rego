# METADATA
# title: "CloudTrail Bucket Access Logging"
# description: "Ensures CloudTrail logging bucket has access logging enabled to detect tampering of log files"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonS3/latest/UG/ManagingBucketLogging.html
# custom:
#   avd_id: AVD-AWS-0322
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: require-bucket-access-logging
#   recommended_action: "Remove the public endpoint from the RDS instance'"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0322

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
	trail.bucketname.value != ""
    bucket := input.aws.s3.buckets[_]
    bucket.name.value == trail.bucketname.value
    not bucket.logging.enabled.value
	res := result.new("Bucket has S3 access logs disabled", bucket.name)
}
