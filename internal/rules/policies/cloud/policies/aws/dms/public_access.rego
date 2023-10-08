# METADATA
# title: "DMS Publicly Accessible Instances"
# description: "Ensure that Amazon Database Migration Service (DMS) instances are not publicly accessible."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.PublicPrivate.html
# custom:
#   avd_id: AVD-AWS-0319
#   provider: aws
#   service: dms
#   severity: LOW
#   short_code: public_access
#   recommended_action: "Ensure that DMS replication instances have only private IP address and not public IP address"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.dms.aws0319

deny[res] {
	replicationinstance := input.aws.dms.replicationinstances[_]
	replicationinstance.publiclyaccessible.value
	res := result.new("DMS replication instance is publicly accessible.", replicationinstance.publiclyaccessible)
}
