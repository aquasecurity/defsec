# METADATA
# title: "ELB Health Check Active"
# description: "Ensures all Auto Scaling groups have ELB health check active.."
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-elb-healthcheck.html
# custom:
#   avd_id: AVD-AWS-0341
#   provider: aws
#   service: autoscaling
#   severity: LOW
#   short_code: elb-health-check-active
#   recommended_action: "Enable ELB health check for the Auto Scaling groups."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.autoscaling.aws0341

deny[res] {
	group := input.aws.autoscaling.autoscalinggroupslist[_]
	not group.healthchecktype.value == "ELB"
	group.loadbalancernames
	res := result.new("Auto Scaling group does not have ELB health check active", group)
}
