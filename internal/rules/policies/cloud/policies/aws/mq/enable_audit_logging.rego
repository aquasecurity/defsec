# METADATA
# title: "MQ Broker Audit Logging Enabled"
# description: "MQ Broker should have audit logging enabled"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html
# custom:
#   avd_id: AVD-AWS-0209
#   provider: aws
#   service: mq
#   severity: MEDUIM
#   short_code: enable-audit-logging
#   recommended_action: "Logging should be enabled to allow tracing of issues and activity to be investigated more fully. Logs provide additional information and context which is often invalauble during investigation"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.mq.aws0209

deny[res] {
	broker := input.aws.mq.brokers[_]
	not broker.logging.audit.value
	res := result.new("Broker does not have audit logging enabled.", broker.logging.audit)
}
