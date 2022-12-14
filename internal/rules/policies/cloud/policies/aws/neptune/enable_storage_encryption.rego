# METADATA
# title: "Neptune Storage Encryption Enable"
# description: "Neptune storage must be encrypted at rest"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html
# custom:
#   avd_id: AVD-AWS-0213
#   provider: aws
#   service: neptune
#   severity: HIGH
#   short_code: enable-storage-encryption
#   recommended_action: "Encryption of Neptune storage ensures that if their is compromise of the disks, the data is still protected."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.neptune.aws0213

deny[res] {
	cluster := input.aws.neptune.clusters[_]
	not cluster.storageencrypted.value
	res := result.new("Cluster does not have storage encryption enabled.", cluster.storageencrypted)
}
