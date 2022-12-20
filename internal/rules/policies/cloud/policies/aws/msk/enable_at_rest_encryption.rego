# METADATA
# title: "MSK Cluster At Rest Encryption"
# description: "A MSK cluster allows unencrypted data at rest."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html
# custom:
#   avd_id: AVD-AWS-0305
#   provider: aws
#   service: msk
#   severity: HIGH
#   short_code: enable-at-rest-encryption
#   recommended_action: "Encryption should be forced for Kafka clusters, including at rest. This ensures sensitive data is kept private."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.msk.aws0305

deny[res] {
	cluster := input.aws.msk.clusters[_]
	not cluster.encryptionatrest.enabled.value
	res := result.new("The cluster is not encrypted at rest.", cluster.encryptionatrest.enabled)
}
