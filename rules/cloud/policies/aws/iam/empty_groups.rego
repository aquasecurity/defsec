# METADATA
# title: "Empty Groups"
# description: "Ensures all groups have at least one member"
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_WorkingWithGroupsAndUsers.html
# custom:
#   avd_id: AVD-AWS-0329
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: empty_groups
#   recommended_action: "Remove unused groups without users"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: iam
#           provider: aws

package builtin.aws.iam.aws0329

deny[res] {
	group := input.aws.iam.groups[_]
	not group.users
	res := result.new("Group does not contain any users", group)
}
