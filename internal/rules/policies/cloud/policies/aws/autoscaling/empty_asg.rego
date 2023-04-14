# METADATA
# title: "Empty AutoScaling Group"
# description: "Ensures all autoscaling groups contain at least 1 instance.."
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://docs.aws.amazon.com/autoscaling/ec2/userguide/AutoScalingGroup.html
# custom:
#   avd_id: AVD-AWS-0340
#   provider: aws
#   service: autoscaling
#   severity: LOW
#   short_code: empty-asg
#   recommended_action: "Delete the unused AutoScaling group."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.autoscaling.aws0340

deny[res] {
	group := input.aws.autoscaling.autoscalinggroupslist[_]
	not group.instances
	res := result.new("Auto scaling group does not contain any instance", group)
}
