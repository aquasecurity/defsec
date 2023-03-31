# METADATA
# title: "RDS Deletion Protection Disabled"
# description: "Ensure deletion protection is enabled for RDS database instances."
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/
# custom:
#   avd_id: AVD-AWS-0177
#   provider: aws
#   service: rds
#   severity: MEDIUM
#   short_code: enable-deletion-protection
#   recommended_action: "Modify the RDS instances to enable deletion protection."
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: rds
#           provider: aws
package builtin.aws.rds.aws0177

deny[res] {
	instance := input.aws.rds.instances[_]
	not instance.deletionprotection.value
	res := result.new("Instance does not have Deletion Protection enabled", instance.deletionprotection)
}
