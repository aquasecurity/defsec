# METADATA
# title: "Mq Broker Public Accessible"
# description: "Ensure MQ Broker is not publicly exposed"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-amazon-mq-securely.html#prefer-brokers-without-public-accessibility
# custom:
#   avd_id: AVD-AWS-0211
#   provider: aws
#   service: mq
#   severity: HIGH
#   short_code: no-public-access
#   recommended_action: "Public access of the MQ broker should be disabled and only allow routes to applications that require access."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.mq.aws0211

deny[res] {
	broker := input.aws.mq.brokers[_]
    broker.publicaccess.value
	res := result.new("Broker has public access enabled.", broker.publicaccess)
}
