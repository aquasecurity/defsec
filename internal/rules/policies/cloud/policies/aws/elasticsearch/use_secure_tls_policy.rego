# METADATA
# title: "Elasticsearch TLS Policy"
# description: "Elasticsearch domain endpoint is using outdated TLS policy."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html
# custom:
#   avd_id: AVD-AWS-0207
#   provider: aws
#   service: elasticsearch
#   severity: HIGH
#   short_code: use-secure-tls-policy
#   recommended_action: "You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.elasticsearch.aws0207

deny[res] {
	domain := input.aws.elasticsearch.domains[_]
	domain.endpoint.tlspolicy.value != "Policy-Min-TLS-1-2-2019-07"
	res := result.new("Domain does not have a secure TLS policy.", domain.endpoint.tlspolicy)
}
