# METADATA
# title: "Password Requires Symbols"
# description: "Ensures password policy requires the use of symbols"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html
# custom:
#   avd_id: AVD-AWS-0336
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: password_requires_symbols
#   recommended_action: "Update the password policy to require the use of symbols"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: iam
#           provider: aws
package builtin.aws.iam.aws0336

deny[res] {
	policy := input.aws.iam.passwordpolicy
	not policy.requiresymbols.value
	res := result.new("Password policy does not require symbols", policy.requiresymbols)
}
