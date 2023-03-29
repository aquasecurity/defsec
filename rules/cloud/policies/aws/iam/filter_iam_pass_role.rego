# METADATA
# title: "IAM Pass Role Filtering"
# description: "Ensures any IAM pass role attched to roles are flagged and warned."
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html  // 
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
#   terraform:
#       good_examples: "rules/cloud/policies/aws/iam/filter_iam_pass_role.tf.go"
#   cloud_formation:
#       good_examples: "rules/cloud/policies/aws/iam/filter_iam_pass_role_check.cf.go"

package builtin.aws.iam.aws0342

deny[res] {
    role := input.aws.iam.roles[_]
    policy := role.policies[_]
    action := policy.document[_]
    contains(action, "iam:PassRole")
    res = result.new("Warning: 'iam:PassRole' action is present in role", role.name)
}
