# METADATA
# title: "RDS IAM Database Authentication Disabled"
# description: "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html
# custom:
#   avd_id: AVD-AWS-0176
#   provider: aws
#   service: rds
#   severity: MEDIUM
#   short_code: enable-iam-auth
#   recommended_action: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication."
#   input:
#     selector:
#     - type: cloud
#       subtype: rds
package builtin.aws.rds.aws0176

deny[res] {
	instance := input.aws.rds.instances[_]
	instance.engine.value == ["postgres", "mysql"][_]
	not instance.iamauthenabled.value
	res := result.new("Instance does not have IAM Authentication enabled", instance.iamauthenabled)
}
