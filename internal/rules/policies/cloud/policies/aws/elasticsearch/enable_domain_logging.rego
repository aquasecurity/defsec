# METADATA
# title: "ElasticSearch Logging Enabled"
# description: "Ensures ElasticSearch domains are configured to log data to CloudWatch"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createdomain-configure-slow-logs.html
# custom:
#   avd_id: AVD-AWS-0204
#   provider: aws
#   service: elasticsearch
#   severity: MEDIUM
#   short_code: enable-domain-logging"
#   recommended_action: "Ensure logging is enabled and a CloudWatch log group is specified for each ElasticSearch domain.'"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.elasticsearch.aws0204

deny[res] {
	domain := input.aws.elasticsearch.domains[_]
	not domain.logpublishing.auditenabled.value
	res := result.new("Domain audit logging is not enabled.", domain.logpublishing.auditenabled)
}