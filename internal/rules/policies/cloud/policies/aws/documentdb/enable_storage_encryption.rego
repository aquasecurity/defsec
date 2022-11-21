# METADATA
# title: "Documentdb Storage Encrypted"
# description: "Ensure documentDB storage must be encrypted"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service: documentdb
#   severity: HIGH
#   short_code: enable-storage-encryption
#   recommended_action: "Encryption of the underlying storage used by DocumentDB ensures that if their is compromise of the disks, the data is still protected."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.documentdb.aws0180

deny[res] {
	cluster := input.aws.documentdb.clusters[_]
	not cluster.storageencrypted.value
	res := result.new("Cluster storage does not have encryption enabled.", cluster.storageencrypted)
}