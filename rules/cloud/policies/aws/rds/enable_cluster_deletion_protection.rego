# METADATA
# title: "RDS Deletion Protection Disabled"
# description: "Ensure deletion protection is enabled for RDS database instances."
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://docs.aws.amazon.com/config/latest/developerguide/rds-cluster-deletion-protection-enabled.html
# custom:
#   avd_id: AVD-AWS-0343
#   provider: aws
#   service: rds
#   severity: MEDIUM
#   short_code: enable-cluster-deletion-protection
#   recommended_action: "Modify the RDS clusters to enable deletion protection."
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: rds
#           provider: aws
package builtin.aws.rds.aws0343

deny[res] {
	cluster := input.aws.rds.clusters[_]
	not cluster.deletionprotection.value
	res := result.new("Cluster does not have Deletion Protection enabled", cluster.deletionprotection)
}
