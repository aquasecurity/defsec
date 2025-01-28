# METADATA
# title: "Container Insights Enabled"
# description: "Ensure that ECS clusters have CloudWatch Container Insights feature enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html
# custom:
#   avd_id: AVD-AWS-0193
#   provider: aws
#   service: ecs
#   severity: LOW
#   short_code: enable-container-insight
#   recommended_action: "Enabled container insights feature for ECS clusters."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.ecs.aws0193

deny[res] {
	cluster := input.aws.ecs.clusters[_]
	not cluster.settings.containerinsightsenabled.value
	res := result.new("Cluster does not have container insights enabled.",cluster.settings.containerinsightsenabled )
}
