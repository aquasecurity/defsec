# METADATA
# title: "MSK Cluster Encryption In-Transit"
# description: "Ensure that TLS encryption within the cluster feature is enabled for your Amazon MSK clusters."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html
# custom:
#   avd_id: AVD-AWS-0302
#   provider: aws
#   service: msk
#   severity: HIGH
#   short_code: enable_transit_cluster_encryption
#   recommended_action: "Enable TLS encryption within the cluster for all MSK clusters"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.msk.aws0302

deny[res] {
	cluster := input.aws.msk.clusters[_]
	not cluster.encryptionintransit.incluster.value
	res := result.new("TLS encryption within the cluster is not enabled", cluster.encryptionintransit.incluster)
}
