# METADATA
# title: "Object Lock Enabled"
# description: "Ensures that AWS CloudTrail S3 buckets use Object Lock for data protection and regulatory compliance."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock-managing.html
# custom:
#   avd_id: AVD-AWS-0326
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: bucket_object_lock
#   recommended_action: "Edit trail to use a bucket with object locking enabled."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0326

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
	trail.bucketname.value != ""
    bucket := input.aws.s3.buckets[_]
    bucket.name.value == trail.bucketname.value
    bucket.objectlockconfiguration.objectlockenabled.value != "enabled"
	res := result.new("Object lock is not enabled for bucket", bucket.name)
}
