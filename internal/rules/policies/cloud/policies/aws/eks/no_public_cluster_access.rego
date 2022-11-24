# METADATA
# title: "EKS Public Aceess"
# description: "EKS Clusters should have the public access disabled"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html
# custom:
#   avd_id: AVD-AWS-0195
#   provider: aws
#   service: eks
#   severity: CRITICAL
#   short_code: no-public-cluster-access
#   recommended_action: "EKS clusters are available publicly by default, this should be explicitly disabled in the vpc_config of the EKS cluster resource."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.eks.aws0195

deny[res] {
	cluster := input.aws.eks.clusters[_]
	cluster.publicaccessenabled.value
	res := result.new("Public cluster access is enabled.", cluster.publicaccessenabled)
}
