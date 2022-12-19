# METADATA
# title: "MSK Cluster Unauthenticated Access"
# description: "Ensure that unauthenticated access feature is disabled for your Amazon MSK clusters."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/msk/latest/developerguide/msk-authentication.html
# custom:
#   avd_id: AVD-AWS-0303
#   provider: aws
#   service: msk
#   severity: HIGH
#   short_code: enable_unauth_access
#   recommended_action: "Ensure that MSK clusters does not have unauthenticated access enabled."
#   input:
#     selector:
#     - type: cloud
package builtin.aws.msk.aws0303

deny[res] {
	cluster := input.aws.msk.clusters[_]
	not cluster.clientauthentication.unauthenticated.enabled.value
	res := result.new("Cluster does not have unauthenticated access enabled", cluster.clientauthentication.unauthenticated.enabled)
}
