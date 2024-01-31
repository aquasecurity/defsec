# METADATA
# title: "Redshift At Rest Encryption"
# description: "Redshift clusters should use at rest encryption."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html
# custom:
#   avd_id: AVD-AWS-0202
#   provider: aws
#   service: redshift
#   severity: HIGH
#   short_code: encryption-customer-key
#   recommended_action: "Redshift clusters that contain sensitive data or are subject to regulation should be encrypted at rest to prevent data leakage should the infrastructure be compromised.`"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.redshift.aws0202

deny[res] {
	cluster := input.aws.redshift.clusters[_]
	not  cluster.encryption.enabled.value
	res := result.new("Cluster does not have encryption enabled.", cluster.encryption.enabled)
    
}{
    cluster := input.aws.redshift.clusters[_]
	cluster.encryption.enabled.value
    cluster.encryption.kmskeyid.value == ""
	res := result.new("Cluster does not use a customer managed encryption key.", cluster.encryption.kmskeyid)
}
