# METADATA
# title: "CloudTrail Bucket Delete Policy"
# description: "Ensures CloudTrail logging bucket has a policy to prevent deletion of logs without an MFA token"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete
# custom:
#   avd_id: AVD-AWS-0323
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: bucket_delete
#   recommended_action: "Enable MFA delete on the CloudTrail bucket"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0323

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
	trail.bucketname.value != ""
    bucket := input.aws.s3.buckets[_]
    bucket.name.value == trail.bucketname.value
    not bucket.versioning.mfadelete.value
	res := result.new("Bucket has MFA delete disabled", bucket.name)
}
