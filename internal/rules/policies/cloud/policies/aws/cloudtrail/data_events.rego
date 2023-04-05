# METADATA
# title: "CloudTrail Data Events"
# description: "Ensure Data events are included into Amazon CloudTrail trails configuration."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html
# custom:
#   avd_id: AVD-AWS-0324
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: data_events
#   recommended_action: "Update CloudTrail to enable data events."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0324

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
	not trail.eventselectors[0].dataresources
	res = result.new("CloudTrail trail does not have Data Events configured", trail)
}
