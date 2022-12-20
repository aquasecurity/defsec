# METADATA
# title: "MSK Cluster Public Access"
# description: "Ensure that public access feature within the cluster is disabled for your Amazon MSK clusters."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/msk/latest/developerguide/public-access.html
# custom:
#   avd_id: AVD-AWS-0304
#   provider: aws
#   service: msk
#   severity: HIGH
#   short_code: public_access
#   recommended_action: "Check for public access feature within the cluster for all MSK clusters"
#   input:
#     selector:
#     - type: cloud
package builtin.aws.msk.aws0304

deny[res] {
	cluster := input.aws.msk.clusters[_]
	cluster.brokernodegroupinfo.connectivityinfo.publicaccess.type.value != "DISABLED"
	res := result.new("'MSK cluster is publicly accessible", cluster.brokernodegroupinfo.connectivityinfo.publicaccess.type)
}
