# METADATA
# title: "Elasticsearch Domain Encryption"
# description: "Elasticsearch domain isn't encrypted at rest."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html
# custom:
#   avd_id: AVD-AWS-0199
#   provider: aws
#   service: elasticsearch
#   severity: HIGH
#   short_code: enable-domain-encryption
#   recommended_action: "You should ensure your Elasticsearch data is encrypted at rest to help prevent sensitive information from being read by unauthorised users."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.elasticsearch.aws0199

deny[res] {
	domain := input.aws.elasticsearch.domains[_]
	not domain.atrestencryption.enabled.value
	res := result.new("Domain does not have at-rest encryption enabled.", domain.atrestencryption.enabled)
}
