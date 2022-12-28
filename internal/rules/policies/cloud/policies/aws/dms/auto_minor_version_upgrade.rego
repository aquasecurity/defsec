# METADATA
# title: "DMS Auto Minor Version Upgrade"
# description: "Ensure that your Amazon Database Migration Service (DMS) replication instances have the Auto Minor Version Upgrade feature enabled"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.Modifying.html
# custom:
#   avd_id: AVD-AWS-0317
#   provider: aws
#   service: dms
#   severity: LOW
#   short_code: auto_minor_version_upgrate
#   recommended_action: "Enable Auto Minor Version Upgrade feature in order to automatically receive minor engine upgrades for improved performance and security"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.dms.aws0317

deny[res] {
	replicationinstance := input.aws.dms.replicationinstances[_]
	not replicationinstance.autominorversionupgrate.value
	res := result.new("Replication instance does not have auto minor version upgrade enabled", replicationinstance.autominorversionupgrate)
}
