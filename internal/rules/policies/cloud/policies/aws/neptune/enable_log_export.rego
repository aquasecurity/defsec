# METADATA
# title: "Neptune Log Export Enable"
# description: "Neptune logs export should be enabled"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html
# custom:
#   avd_id: AVD-AWS-0212
#   provider: aws
#   service: neptune
#   severity: MEDUIM
#   short_code: enable-log-export
#   recommended_action: "Neptune does not have auditing by default. To ensure that you are able to accurately audit the usage of your Neptune instance you should enable export logs."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.neptune.aws0212

deny[res] {
	cluster := input.aws.neptune.clusters[_]
	not cluster.logging.audit.value
	res := result.new("Cluster does not have audit logging enabled.", cluster.logging.audit)
}
