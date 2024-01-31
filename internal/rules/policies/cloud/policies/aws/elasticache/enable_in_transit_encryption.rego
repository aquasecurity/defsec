# METADATA
# title: "ElastiCache Redis Cluster Encryption In-Transit"
# description: "Ensure that your AWS ElastiCache Redis clusters have encryption in-transit enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html
# custom:
#   avd_id: AVD-AWS-0198
#   provider: aws
#   service: elasticache
#   severity: HIGH
#   short_code: enable-in-transit-encryption
#   recommended_action: "Enable in-transit encryption for ElastiCache clusters"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.elasticache.aws0198

deny[res] {
	group := input.aws.elasticache.replicationgroups[_]
	not group.transitencryptionenabled.value
	res := result.new("Replication group does not have transit encryption enabled.", group.transitencryptionenabled)
}