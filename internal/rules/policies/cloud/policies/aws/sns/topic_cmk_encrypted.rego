# METADATA
# title: "SNS Topic CMK Encryption'"
# description: "Ensures Amazon SNS topics are encrypted with KMS Customer Master Keys (CMKs)."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html
# custom:
#   avd_id: AVD-AWS-0300
#   provider: aws
#   service: sns
#   severity: HIGH
#   short_code: topic_cmk_encrypted
#   recommended_action: "Update SNS topics to use Customer Master Keys (CMKs) for Server-Side Encryption."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.sns.aws0300

deny[res] {
	topic := input.aws.sns.topics[_]
	topic.encryption.kmskeyid.value == ""
	res := result.new("Topic does not have encryption enabled.", topic.encryption.kmskeyid)
}{
    topic := input.aws.sns.topics[_]
	topic.encryption.kmskeyid.value == "alias/aws/sns"
    res := result.new("SNS topic is using default KMS key for Server-Side Encryption", topic.encryption.kmskeyid)

}
