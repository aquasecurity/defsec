# METADATA
# title: "ElasticSearch HTTPS Only"
# description: "Ensures ElasticSearch domains are configured to enforce HTTPS connections"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html
# custom:
#   avd_id: AVD-AWS-0206
#   provider: aws
#   service: elasticsearch
#   severity: CRITICAl
#   short_code: enforce-https
#   recommended_action: "Ensure HTTPS connections are enforced for all ElasticSearch domains."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.elasticsearch.aws0206

deny[res] {
	domain := input.aws.elasticsearch.domains[_]
	not domain.endpoint.enforcehttps.value
	res := result.new("Domain does not enforce HTTPS.", domain.endpoint.enforcehttps)
}
