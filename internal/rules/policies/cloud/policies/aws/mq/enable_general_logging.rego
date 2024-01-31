# METADATA
# title: "Mq Broker General Logging Enable"
# description: "MQ Broker should have general logging enabled"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html
# custom:
#   avd_id: AVD-AWS-0210
#   provider: aws
#   service: mq
#   severity: LOW
#   short_code: enable-general-logging
#   recommended_action: "Logging should be enabled to allow tracing of issues and activity to be investigated more fully. Logs provide additional information and context which is often invalauble during investigation"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.mq.aws0210

deny[res] {
	broker := input.aws.mq.brokers[_]
	not broker.logging.general.value
	res := result.new("Broker does not have general logging enabled.", broker.logging.general)
}
