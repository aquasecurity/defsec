# METADATA
# title: "Default VPC Exists"
# description: "Determines whether the default VPC exists."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html
# custom:
#   avd_id: AVD-AWS-0183
#   provider: aws
#   service: ec2
#   severity: HIGH
#   short_code: no-default-vpc
#   recommended_action: "Move resources from the default VPC to a new VPC created for that application or resource group."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.ec2.aws0183

deny[res] {
	def := input.aws.ec2.vpcs[_]
	def.isdefault.value
	res := result.new("Default VPC is used.", def.isdefault)
}