# METADATA
# title: "MSK Cluster Client Broker Encryption"
# description: "Ensure that only TLS encryption between the client and broker feature is enabled for your Amazon MSK clusters."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html
# custom:
#   avd_id: AVD-AWS-0301
#   provider: aws
#   service: msk
#   severity: HIGH
#   short_code: enable_in_transit_encryption
#   recommended_action: "Enable only TLS encryption between the client and broker for all MSK clusters"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.msk.aws0301

deny[res] {
	cluster := input.aws.msk.clusters[_]
	cluster.encryptionintransit.clientbroker.value != "TLS"
	res := result.new("Encryption between the client and broker is not only TLS encrypted", cluster.encryptionintransit.clientbroker)
}
