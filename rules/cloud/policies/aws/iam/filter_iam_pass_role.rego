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


allows_permission(statements, permission, effect) {
    statement := statements[_]
    statement.Effect == effect
    action = statement.Action[_]
    action == permission
}

deny[res] {
    policy := input.aws.iam.policies[_]
    value = json.unmarshal(policy.document.value)
    statements = value.Statement
    not allows_permission(statements, "iam:PassRole", "Deny")
    allows_permission(statements, "iam:PassRole", "Allow")
    res = result.new("IAM policy allows 'iam:PassRole' action", policy.document)
}