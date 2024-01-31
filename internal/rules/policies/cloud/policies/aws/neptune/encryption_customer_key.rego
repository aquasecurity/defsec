# METADATA
# title: "Neptune Customer Key Encryption"
# description: "Neptune encryption should use Customer Managed Keys"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html
# custom:
#   avd_id: AVD-AWS-0214
#   provider: aws
#   service: neptune
#   severity: HIGH
#   short_code: encryption-customer-key
#   recommended_action: "Encryption using AWS keys provides protection for your Neptune underlying storage. To increase control of the encryption and manage factors like rotation use customer managed keys."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.neptune.aws0214

deny[res] {
	cluster := input.aws.neptune.clusters[_]
	cluster.kmskeyid.value == ""
	res := result.new("Cluster does not encrypt data with a customer managed key.", cluster.kmskeyid)
}
