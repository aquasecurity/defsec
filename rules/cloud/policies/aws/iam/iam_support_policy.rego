# METADATA
# title: "IAM Support Policy"
# description: "Ensures that an IAM role, group or user exists with specific permissions to access support center."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/awssupport/latest/user/accessing-support.html
# custom:
#   avd_id: AVD-AWS-0330
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: iam_support_policy
#   recommended_action: "Ensure that an IAM role has permission to access support center."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.iam.aws0330

deny[res] {
    found := [policy| policy = input.aws.iam.policies[_]; policy.name.value == "AWSSupportAccess"]
    count(found) == 0
	res := result.new("No role, user or group attached to the AWSSupportAccess policy", "")
}
