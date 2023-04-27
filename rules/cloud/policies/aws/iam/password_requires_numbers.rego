# METADATA
# title: "Password Requires Numbers"
# description: "Ensures password policy requires the use of numbers"
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html
# custom:
#   avd_id: AVD-AWS-0334
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: password_requires_lowercase
#   recommended_action: "Update the password policy to require the use of numbers"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: iam
#           provider: aws
package builtin.aws.iam.aws0334

deny[res] {
	policy := input.aws.iam.passwordpolicy
	not policy.requirenumbers.value
	res := result.new("Password policy does not require numbers", policy.requirenumbers)
}
