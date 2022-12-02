# METADATA
# title: "CloudTrail Enabled Global Services"
# description: "Ensures CloudTrail is enabled for all regions within an account."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-getting-started.html
# custom:
#   avd_id: AVD-AWS-0200
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: enable-public-access
#   recommended_action: "Enable CloudTrail for all regions and ensure that at least one region monitors global service events"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0200

deny[res] {
    trail := input.aws.cloudtrail.trails[_]
	not trail.includeglobalserviceevents.value
	res := result.new("trail is not global enable", trail.includeglobalserviceevents) 
}
