# METADATA
# title: "Password Requires Lowercase"
# description: "Ensures password policy requires at least one lowercase letter"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html
# custom:
#   avd_id: AVD-AWS-0333
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: password_requires_lowercase
#   recommended_action: "Update the password policy to require the use of lowercase letters"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.iam.aws0333

deny[res] {
	policy := input.aws.iam.passwordpolicy
    not policy.requirelowercase.value
	res := result.new("Password policy does not require lowercase characters", policy.requirelowercase)
}
