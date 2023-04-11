# METADATA
# title: "IAM User Present"
# description: "Ensure that at least one IAM user exists so that access to your AWS services and resources is made only through IAM users instead of the root account."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
# custom:
#   avd_id: AVD-AWS-0331
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: iam_user_present
#   recommended_action: "Create IAM user(s) and use them to access AWS services and resources."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.iam.aws0331

deny[res] {
	count(input.aws.iam.users) == 0
	res := result.new("No users found", "")
}
