# METADATA
# title: "CloudTrail Management Events"
# description: "Ensures that AWS CloudTrail trails are configured to log management events."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html
# custom:
#   avd_id: AVD-AWS-0327
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: management_events
#   recommended_action: "Update CloudTrail to enable management events logging."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0327

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
    trail.eventselectors.includemanagementevents.value == ""
	res := result.new("CloudTrail trail is not configured to log management events", trail.eventselectors.includemanagementevents)
}
