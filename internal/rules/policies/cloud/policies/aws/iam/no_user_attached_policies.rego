# METADATA
# title: "IAM User Attached"
# description: "IAM policies should not be granted directly to users."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://console.aws.amazon.com/iam/
# custom:
#   avd_id: AVD-AWS-0208
#   provider: aws
#   service: iam
#   severity: LOW
#   short_code: no-user-attached-policies
#   recommended_action: "CIS recommends that you apply IAM policies directly to groups and roles but not users. Assigning privileges at the group or role level reduces the complexity of access management as the number of users grow. Reducing access management complexity might in turn reduce opportunity for a principal to inadvertently receive or retain excessive privileges"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.iam.aws0208

deny[res] {
	user := input.aws.iam.users[_]
	not count(user.policies) == 0
	res := result.new("One or more policies are attached directly to a user", user.policies)
}
    