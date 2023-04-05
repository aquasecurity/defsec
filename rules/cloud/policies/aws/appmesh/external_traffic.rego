# METADATA
# title: "App Mesh Restrict External Traffic"
# description: "Ensure that Amazon App Mesh virtual nodes have egress only access to other defined resources available within the service mesh."
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - https://docs.aws.amazon.com/app-mesh/latest/userguide/security.html
# custom:
#   avd_id: AVD-AWS-0337
#   provider: aws
#   service: appmesh
#   severity: LOW
#   short_code: external_traffic
#   recommended_action: "Deny all traffic to the external services"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: appmeash
#           provider: aws
package builtin.aws.appmesh.aws0337

deny[res] {
	mesh := input.aws.appmesh.meshes[_]
	mesh.spec.egressfilter.type.value == "ALLOW_ALL"
	res := result.new("App Mesh mesh allows access to external services", mesh.spec)
}
