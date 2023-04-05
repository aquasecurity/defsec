# METADATA
# title: "IAM Pass Role Filtering"
# description: "Ensures any IAM pass role attched to roles are flagged and warned."
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html 
# custom:
#   avd_id: AVD-AWS-0342
#   provider: aws
#   service: iam
#   severity: MEDIUM
#   short_code: filer-passrole-access
#   recommended_action: "Resolve permission escalations by denying pass role'"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: iam
#           provider: aws
package builtin.aws.iam.aws0342

deny[res] {
	policy := input.aws.iam.policies[_]
	action := policy.document.value
	contains(action, "iam:PassRole")
    msg := sprintf("Warning: 'iam:PassRole' action is present in policy %v", [action])
    res = result.new(msg, policy.name)
}
