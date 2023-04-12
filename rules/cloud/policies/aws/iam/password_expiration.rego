# METADATA
# title: "Password Expiration"
# description: "Ensures password policy enforces a password expiration"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html
# custom:
#   avd_id: AVD-AWS-0332
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: password_expiration
#   recommended_action: "Enable password expiration for the account"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: iam
#           provider: aws
package builtin.aws.iam.aws0332

deny[res] {
	policy := input.aws.iam.passwordpolicy
	not policy.expirepasswords.value
	res := result.new("Password expiration policy is not set to expire passwords", policy.expirepasswords)
}

deny[res] {
	policy := input.aws.iam.passwordpolicy
	policy.expirepasswords.value
	policy.maxagedays.value > 180
	res := result.new("Password expiration days is greater than 180", policy.maxagedays)
}
