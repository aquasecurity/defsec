# METADATA
# title: "Elasticsearch Domain Encrytion"
# description: "Elasticsearch domain uses plaintext traffic for node to node communication."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html
# custom:
#   avd_id: AVD-AWS-0205
#   provider: aws
#   service: elasticsearch
#   severity: HIGH
#   short_code: enable-in-transit-encryption
#   recommended_action: "Traffic flowing between Elasticsearch nodes should be encrypted to ensure sensitive data is kept private."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.elasticsearch.aws0205

deny[res] {
	domain := input.aws.elasticsearch.domains[_]
	not domain.transitencryption.enabled.value
	res := result.new("Domain does not have in-transit encryption enabled.", domain.transitencryption.enabled)
}
