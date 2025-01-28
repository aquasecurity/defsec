# METADATA
# title: "Elasticache Security Group Description"
# description: "Missing description for security group/security group rule."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonElastiCache/latest/mem-ug/SecurityGroups.Creating.html
# custom:
#   avd_id: AVD-AWS-0196
#   provider: aws
#   service: elasticache
#   severity: LOW
#   short_code: add-description-for-security-group
#   recommended_action: "Security groups and security group rules should include a description for auditing purposes. Simplifies auditing, debugging, and managing security groups."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.elasticache.aws0196

deny[res] {
	sg := input.aws.elasticache.securitygroups[_]
	sg.description.value == ""
	res := result.new("Security group does not have a description.", sg.description)
}
