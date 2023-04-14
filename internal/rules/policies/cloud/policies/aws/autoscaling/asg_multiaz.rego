# METADATA
# title: "ASG Multiple AZ"
# description: "Ensures that ASGs are created to be cross-AZ for high availability."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/autoscaling/latest/userguide/AutoScalingGroup.html
# custom:
#   avd_id: AVD-AWS-0339
#   provider: aws
#   service: autoscaling
#   severity: LOW
#   short_code: asg-multi-az
#   recommended_action: "Modify the autoscaling instance to enable scaling across multiple availability zones."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.autoscaling.aws0339

deny[res] {
	group := input.aws.autoscaling.autoscalinggroupslist[_]
	count(group.avaiabilityzone) <= 1
	res := result.new(sprintf("Auto scaling group is only using (%v) availibility zones", [count(group.avaiabilityzone)]), group)
}
