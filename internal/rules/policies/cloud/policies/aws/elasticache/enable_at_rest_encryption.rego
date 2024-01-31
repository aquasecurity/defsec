# METADATA
# title: "ElastiCache Redis Cluster Encryption At-Rest"
# description: "Ensure that your Amazon ElastiCache Redis clusters are encrypted to increase data security."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html
# custom:
#   avd_id: AVD-AWS-0197
#   provider: aws
#   service: elasticache
#   severity: HIGH
#   short_code: enable-at-rest-encryption
#   recommended_action: "Enable encryption for ElastiCache cluster data-at-rest"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.elasticache.aws0197

deny[res] {
	group := input.aws.elasticache.replicationgroups[_]
	not group.atrestencryptionenabled.value
	res := result.new("Replication group does not have at-rest encryption enabled.", group.atrestencryptionenabled)
}
