# METADATA
# title: "cloudtrail multiregion enable"
# description: "Ensure multiregion is enabled"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html
# custom:
#   avd_id: AVD-AWS-0179
#   provider: aws
#   service: cloudtrail
#   severity: MEDIUM
#   short_code: enable-all-regions
#   recommended_action: "When creating Cloudtrail in the AWS Management Console the trail is configured by default to be multi-region, this isn't the case with the Terraform resource. Cloudtrail should cover the full AWS account to ensure you can track changes in regions you are not actively operting in."
#   input:
#     selector:
#     - type: cloud

package builtin.aws.cloudtrail.aws0179

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
	not trail.ismultiregion.value
	res := result.new("cloudtrail does not have multiregion enabled", trail.ismultiregion)
}