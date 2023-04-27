# METADATA
# title: "Password Requires Uppercase"
# description: "Ensures password policy requires at least one uppercase letter"
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html
# custom:
#   avd_id: AVD-AWS-0335
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: password_requires_uppercase
#   recommended_action: "Update the password policy to require the use of uppercase letters"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: iam
#           provider: aws
package builtin.aws.iam.aws0335

deny[res] {
	policy := input.aws.iam.passwordpolicy
	not policy.requireuppercase.value
	res := result.new("Password policy does not require uppercase characters", policy.requireuppercase)
}
