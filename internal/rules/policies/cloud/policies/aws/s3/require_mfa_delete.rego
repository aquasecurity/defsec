# METADATA
# title: "S3 Bucket Deletion Protection"
# description: "Buckets should have MFA deletion protection enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html
# custom:
#   avd_id: AVD-AWS-0217
#   provider: aws
#   service: s3
#   severity: LOW
#   short_code: require-mfa-delete
#   recommended_action: "Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete an object version, adding another layer of security in the event your security credentials are compromised or unauthorized access is obtained."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.s3.aws0217

deny[res] {
	bucket := input.aws.s3.buckets[_]
	not bucket.versioning.mfadelete.value
	res := result.new("Bucket does not have MFA deletion protection enabled", bucket.versioning.mfadelete.value)
}
