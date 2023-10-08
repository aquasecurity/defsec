# METADATA
# title: "DMS Multi-AZ Feature Enabled"
# description: "Ensure that your Amazon Database Migration Service (DMS) replication instances are using Multi-AZ deployment configurations."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.html
# custom:
#   avd_id: AVD-AWS-0318
#   provider: aws
#   service: dms
#   severity: LOW
#   short_code: enable_multiaz
#   recommended_action: "Enable Multi-AZ deployment feature in order to get high availability and failover support"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.dms.aws0318

deny[res] {
	replicationinstance := input.aws.dms.replicationinstances[_]
	not replicationinstance.multiaz.value
	res := result.new("DMS replication instance does not have Multi-AZ feature enabled", replicationinstance.multiaz)
}
